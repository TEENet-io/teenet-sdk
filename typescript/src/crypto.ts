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

import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { hmac } from '@noble/hashes/hmac';
import { Protocol, Curve, ProtocolType, CurveType } from './types';

/**
 * Verify a cryptographic signature
 */
export function verifySignature(
  message: Buffer,
  publicKey: Buffer,
  signature: Buffer,
  protocol: string,
  curve: string
): boolean {
  const protocolLower = protocol.toLowerCase() as ProtocolType;
  const curveLower = curve.toLowerCase() as CurveType;

  switch (curveLower) {
    case Curve.ED25519:
      return verifyED25519(message, publicKey, signature);
    case Curve.SECP256K1:
      return verifySecp256k1(message, publicKey, signature, protocolLower);
    case Curve.SECP256R1:
      return verifySecp256r1(message, publicKey, signature, protocolLower);
    default:
      throw new Error(`Unsupported curve: ${curve}`);
  }
}

/**
 * Verify ED25519 signature (EdDSA)
 */
function verifyED25519(message: Buffer, publicKey: Buffer, signature: Buffer): boolean {
  if (publicKey.length !== 32) {
    throw new Error(`Invalid ED25519 public key size: expected 32, got ${publicKey.length}`);
  }
  if (signature.length !== 64) {
    throw new Error(`Invalid ED25519 signature size: expected 64, got ${signature.length}`);
  }

  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Verify secp256k1 signature (ECDSA or Schnorr)
 */
function verifySecp256k1(
  message: Buffer,
  publicKey: Buffer,
  signature: Buffer,
  protocol: ProtocolType
): boolean {
  // Parse public key - handle different formats
  let pubKeyBytes: Uint8Array;
  if (publicKey.length === 64) {
    // Raw format - add uncompressed prefix
    pubKeyBytes = new Uint8Array(65);
    pubKeyBytes[0] = 0x04;
    pubKeyBytes.set(publicKey, 1);
  } else {
    pubKeyBytes = publicKey;
  }

  if (protocol === Protocol.Schnorr) {
    return verifySecp256k1Schnorr(message, pubKeyBytes, signature);
  } else {
    return verifySecp256k1ECDSA(message, pubKeyBytes, signature);
  }
}

/**
 * Verify secp256k1 ECDSA signature
 */
function verifySecp256k1ECDSA(
  message: Buffer,
  publicKey: Uint8Array,
  signature: Buffer
): boolean {
  try {
    let messageHash: Uint8Array;
    let r: bigint, s: bigint;

    if (signature.length === 65) {
      // Ethereum-style signature with recovery id: r(32) + s(32) + v(1)
      messageHash = keccak_256(message);
      r = BigInt('0x' + signature.subarray(0, 32).toString('hex'));
      s = BigInt('0x' + signature.subarray(32, 64).toString('hex'));
    } else if (signature.length === 64) {
      // Raw r,s format
      messageHash = sha256(message);
      r = BigInt('0x' + signature.subarray(0, 32).toString('hex'));
      s = BigInt('0x' + signature.subarray(32, 64).toString('hex'));
    } else {
      // Try DER format
      messageHash = sha256(message);
      const parsed = parseDERSignature(signature);
      r = parsed.r;
      s = parsed.s;
    }

    // Serialize signature to raw format for verification
    const rHex = r.toString(16).padStart(64, '0');
    const sHex = s.toString(16).padStart(64, '0');
    const sigBytes = Buffer.from(rHex + sHex, 'hex');
    return secp256k1.verify(sigBytes, messageHash, publicKey);
  } catch {
    return false;
  }
}

/**
 * Verify secp256k1 Schnorr signature (BIP-340)
 */
function verifySecp256k1Schnorr(
  message: Buffer,
  publicKey: Uint8Array,
  signature: Buffer
): boolean {
  if (signature.length !== 64) {
    throw new Error(`Invalid Schnorr signature size: expected 64, got ${signature.length}`);
  }

  try {
    const messageHash = sha256(message);
    // Get x-only public key for Schnorr
    const pubPoint = secp256k1.ProjectivePoint.fromHex(publicKey);
    const xOnlyPubKey = pubPoint.toRawBytes(true).subarray(1); // Remove prefix, get 32-byte x

    // Import schnorr from secp256k1
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { schnorr } = require('@noble/curves/secp256k1');
    return schnorr.verify(signature, messageHash, xOnlyPubKey);
  } catch {
    return false;
  }
}

/**
 * Verify secp256r1 (P-256) signature
 */
function verifySecp256r1(
  message: Buffer,
  publicKey: Buffer,
  signature: Buffer,
  protocol: ProtocolType
): boolean {
  // Parse public key
  let pubKeyBytes: Uint8Array;
  if (publicKey.length === 64) {
    // Raw format - add uncompressed prefix
    pubKeyBytes = new Uint8Array(65);
    pubKeyBytes[0] = 0x04;
    pubKeyBytes.set(publicKey, 1);
  } else {
    pubKeyBytes = publicKey;
  }

  if (protocol === Protocol.Schnorr) {
    return verifyP256Schnorr(message, pubKeyBytes, signature);
  } else {
    return verifyP256ECDSA(message, pubKeyBytes, signature);
  }
}

/**
 * Verify P-256 ECDSA signature
 */
function verifyP256ECDSA(
  message: Buffer,
  publicKey: Uint8Array,
  signature: Buffer
): boolean {
  try {
    const messageHash = sha256(message);
    let r: bigint, s: bigint;

    if (signature.length === 64) {
      // Raw r,s format
      r = BigInt('0x' + signature.subarray(0, 32).toString('hex'));
      s = BigInt('0x' + signature.subarray(32, 64).toString('hex'));
    } else {
      // DER format
      const parsed = parseDERSignature(signature);
      r = parsed.r;
      s = parsed.s;
    }

    const rHex = r.toString(16).padStart(64, '0');
    const sHex = s.toString(16).padStart(64, '0');
    const sigBytes = Buffer.from(rHex + sHex, 'hex');
    return p256.verify(sigBytes, messageHash, publicKey);
  } catch {
    return false;
  }
}

/**
 * Verify P-256 Schnorr signature
 */
function verifyP256Schnorr(
  message: Buffer,
  publicKey: Uint8Array,
  signature: Buffer
): boolean {
  if (signature.length !== 64) {
    throw new Error(`Invalid Schnorr signature length: expected 64, got ${signature.length}`);
  }

  try {
    const pubPoint = p256.ProjectivePoint.fromHex(publicKey);
    const curveOrder = p256.CURVE.n;
    const curveP = p256.CURVE.Fp.ORDER;

    const r = BigInt('0x' + signature.subarray(0, 32).toString('hex'));
    const s = BigInt('0x' + signature.subarray(32, 64).toString('hex'));

    if (r <= 0n || s <= 0n || r >= curveOrder || s >= curveOrder) {
      return false;
    }

    // Hash: e = H(r || P.x || message)
    const rBytes = signature.subarray(0, 32);
    const pxBytes = pubPoint.toRawBytes(false).subarray(1, 33);
    const hashInput = Buffer.concat([rBytes, pxBytes, message]);
    const eBytes = sha256(hashInput);
    const e = BigInt('0x' + Buffer.from(eBytes).toString('hex')) % curveOrder;

    // Verify: R = s*G - e*P
    const sG = p256.ProjectivePoint.BASE.multiply(s);
    const eP = pubPoint.multiply(e);
    const R = sG.subtract(eP);

    return R.x === r;
  } catch {
    return false;
  }
}

/**
 * Parse DER-encoded ECDSA signature
 */
function parseDERSignature(sig: Buffer): { r: bigint; s: bigint } {
  let offset = 0;

  // SEQUENCE tag
  if (sig[offset++] !== 0x30) {
    throw new Error('Invalid DER signature: expected SEQUENCE');
  }

  // Length
  let length = sig[offset++];
  if (length & 0x80) {
    const lenBytes = length & 0x7f;
    length = 0;
    for (let i = 0; i < lenBytes; i++) {
      length = (length << 8) | sig[offset++];
    }
  }

  // INTEGER tag for r
  if (sig[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: expected INTEGER for r');
  }

  const rLen = sig[offset++];
  let rBytes = sig.subarray(offset, offset + rLen);
  offset += rLen;

  // Skip leading zeros
  while (rBytes[0] === 0 && rBytes.length > 1) {
    rBytes = rBytes.subarray(1);
  }

  // INTEGER tag for s
  if (sig[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: expected INTEGER for s');
  }

  const sLen = sig[offset++];
  let sBytes = sig.subarray(offset, offset + sLen);

  // Skip leading zeros
  while (sBytes[0] === 0 && sBytes.length > 1) {
    sBytes = sBytes.subarray(1);
  }

  const r = BigInt('0x' + Buffer.from(rBytes).toString('hex'));
  const s = BigInt('0x' + Buffer.from(sBytes).toString('hex'));

  return { r, s };
}

/**
 * Verify HMAC-SHA256 signature
 */
export function verifyHMACSHA256(
  message: Buffer,
  secret: Buffer,
  signature: Buffer
): boolean {
  const expectedMac = hmac(sha256, secret, message);

  if (signature.length !== expectedMac.length) {
    return false;
  }

  // Constant-time comparison
  let result = 0;
  for (let i = 0; i < signature.length; i++) {
    result |= signature[i] ^ expectedMac[i];
  }

  return result === 0;
}
