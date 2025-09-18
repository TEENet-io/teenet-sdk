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

import * as crypto from 'crypto';
import { ec as EC } from 'elliptic';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { Protocol, Curve } from '../types';
import BN from 'bn.js';

// Set SHA512 for ed25519
ed.hashes.sha512 = (message: Uint8Array) => sha512(message);

// ASN.1 module declaration
const asn1 = require('asn1.js');

// ASN.1 definition for ECDSA signature
const ECDSASignature = asn1.define('ECDSASignature', function(this: any) {
  this.seq().obj(
    this.key('r').int(),
    this.key('s').int()
  );
});

/**
 * Verifies a signature against a message and public key
 * Supports all protocol/curve combinations:
 * - ED25519 with EdDSA (protocol parameter ignored for ED25519)
 * - SECP256K1 with ECDSA or Schnorr protocols
 * - SECP256R1 with ECDSA or Schnorr protocols
 */
export async function verifySignature(
  message: Buffer,
  publicKey: Buffer,
  signature: Buffer,
  protocol: typeof Protocol[keyof typeof Protocol],
  curve: typeof Curve[keyof typeof Curve]
): Promise<boolean> {
  try {
    switch (curve) {
      case Curve.ED25519:
        return await verifyED25519(message, publicKey, signature);
      case Curve.SECP256K1:
        return verifySecp256k1(message, publicKey, signature, protocol);
      case Curve.SECP256R1:
        return verifySecp256r1(message, publicKey, signature, protocol);
      default:
        throw new Error(`Unsupported curve: ${curve}`);
    }
  } catch (error) {
    console.error('Verification error:', error);
    return false;
  }
}

/**
 * Verifies ED25519 signatures
 */
async function verifyED25519(message: Buffer, publicKey: Buffer, signature: Buffer): Promise<boolean> {
  // ED25519 only supports EdDSA (not ECDSA or Schnorr)
  if (publicKey.length !== 32) {
    throw new Error(`Invalid ED25519 public key size: expected 32, got ${publicKey.length}`);
  }
  if (signature.length !== 64) {
    throw new Error(`Invalid ED25519 signature size: expected 64, got ${signature.length}`);
  }

  // Use @noble/ed25519 for ED25519 verification
  return await ed.verify(signature, message, publicKey);
}

/**
 * Verifies signatures on secp256k1 curve
 */
function verifySecp256k1(
  message: Buffer,
  publicKeyBytes: Buffer,
  signature: Buffer,
  protocol: typeof Protocol[keyof typeof Protocol]
): boolean {
  const ec = new EC('secp256k1');
  
  // Parse public key
  const key = parseSecp256k1PublicKey(ec, publicKeyBytes);
  
  switch (protocol) {
    case Protocol.ECDSA:
      return verifyECDSA(ec, message, key, signature);
    case Protocol.SCHNORR:
      return verifySchnorr(ec, message, key, signature);
    default:
      throw new Error(`Unsupported protocol for secp256k1: ${protocol}`);
  }
}

/**
 * Verifies signatures on secp256r1 curve (NIST P-256)
 */
function verifySecp256r1(
  message: Buffer,
  publicKeyBytes: Buffer,
  signature: Buffer,
  protocol: typeof Protocol[keyof typeof Protocol]
): boolean {
  const ec = new EC('p256');
  
  // Parse public key
  const key = parseSecp256r1PublicKey(ec, publicKeyBytes);
  
  switch (protocol) {
    case Protocol.ECDSA:
      return verifyECDSA(ec, message, key, signature);
    case Protocol.SCHNORR:
      return verifySchnorr(ec, message, key, signature);
    default:
      throw new Error(`Unsupported protocol for secp256r1: ${protocol}`);
  }
}

/**
 * Verifies ECDSA signature
 */
function verifyECDSA(ec: EC, message: Buffer, key: any, signature: Buffer): boolean {
  // For Ethereum-style signatures (65 bytes), use Keccak-256
  // For other signatures, use SHA-256
  let messageHash: Buffer;
  
  if (signature.length === 65) {
    // Ethereum uses Keccak-256 for message hashing
    messageHash = Buffer.from(keccak_256(message));
  } else {
    // Standard uses SHA-256
    messageHash = crypto.createHash('sha256').update(message).digest();
  }
  
  let sig: { r: BN; s: BN };
  
  // Check signature format
  if (signature.length === 65) {
    // Ethereum-style signature with recovery id: r(32) + s(32) + v(1)
    sig = {
      r: new BN(signature.slice(0, 32)),
      s: new BN(signature.slice(32, 64))
    };
    // Recovery id is signature[64], but we don't need it for verification
  } else if (signature.length === 64) {
    // Raw r,s format without recovery id
    sig = {
      r: new BN(signature.slice(0, 32)),
      s: new BN(signature.slice(32, 64))
    };
  } else {
    // Try to parse as DER format
    try {
      const decoded = ECDSASignature.decode(signature, 'der');
      sig = { r: decoded.r, s: decoded.s };
    } catch {
      throw new Error(`Invalid signature format: length ${signature.length}`);
    }
  }
  
  // Verify the signature
  return key.verify(messageHash, sig);
}

/**
 * Verifies Schnorr signature
 */
function verifySchnorr(ec: EC, message: Buffer, key: any, signature: Buffer): boolean {
  if (signature.length !== 64) {
    throw new Error(`Invalid Schnorr signature length: expected 64, got ${signature.length}`);
  }
  
  const r = new BN(signature.slice(0, 32));
  const s = new BN(signature.slice(32, 64));
  
  // Hash: e = H(r || P.x || message)
  const hasher = crypto.createHash('sha256');
  hasher.update(r.toBuffer('be', 32));
  hasher.update(key.getPublic().getX().toBuffer('be', 32));
  hasher.update(message);
  const e = new BN(hasher.digest());
  
  // Verify: R = s*G - e*P
  const curve = ec.curve;
  const G = ec.g;
  
  // Calculate s*G
  const sG = G.mul(s);
  
  // Calculate e*P
  const eP = key.getPublic().mul(e);
  
  // Calculate R = s*G - e*P
  const R = sG.add(eP.neg());
  
  // Verify that R.x == r
  return R.getX().eq(r);
}

/**
 * Parses a secp256k1 public key from bytes
 * Supports multiple formats:
 * - Uncompressed: 0x04 + 32 bytes X + 32 bytes Y (65 bytes total)
 * - Compressed: 0x02/0x03 + 32 bytes X (33 bytes total)
 * - Raw coordinates: 32 bytes X + 32 bytes Y (64 bytes total)
 */
function parseSecp256k1PublicKey(ec: EC, publicKeyBytes: Buffer): any {
  switch (publicKeyBytes.length) {
    case 65:
      // Uncompressed format: 0x04 + X + Y
      if (publicKeyBytes[0] !== 0x04) {
        throw new Error(`Invalid uncompressed public key prefix: expected 0x04, got 0x${publicKeyBytes[0].toString(16)}`);
      }
      return ec.keyFromPublic(publicKeyBytes);
      
    case 33:
      // Compressed format: 0x02/0x03 + X
      if (publicKeyBytes[0] !== 0x02 && publicKeyBytes[0] !== 0x03) {
        throw new Error(`Invalid compressed public key prefix: expected 0x02 or 0x03, got 0x${publicKeyBytes[0].toString(16)}`);
      }
      return ec.keyFromPublic(publicKeyBytes);
      
    case 64:
      // Raw format: X + Y (add 0x04 prefix)
      const uncompressed = Buffer.concat([Buffer.from([0x04]), publicKeyBytes]);
      return ec.keyFromPublic(uncompressed);
      
    default:
      throw new Error(`Unsupported secp256k1 public key format: length ${publicKeyBytes.length}`);
  }
}

/**
 * Parses a secp256r1 (P-256) public key from bytes
 * Supports multiple formats:
 * - Uncompressed: 0x04 + 32 bytes X + 32 bytes Y (65 bytes total)
 * - Compressed: 0x02/0x03 + 32 bytes X (33 bytes total)
 * - Raw coordinates: 32 bytes X + 32 bytes Y (64 bytes total)
 */
function parseSecp256r1PublicKey(ec: EC, publicKeyBytes: Buffer): any {
  switch (publicKeyBytes.length) {
    case 65:
      // Uncompressed format: 0x04 + X + Y
      if (publicKeyBytes[0] !== 0x04) {
        throw new Error(`Invalid uncompressed public key prefix: expected 0x04, got 0x${publicKeyBytes[0].toString(16)}`);
      }
      return ec.keyFromPublic(publicKeyBytes);
      
    case 33:
      // Compressed format: 0x02/0x03 + X
      if (publicKeyBytes[0] !== 0x02 && publicKeyBytes[0] !== 0x03) {
        throw new Error(`Invalid compressed public key prefix: expected 0x02 or 0x03, got 0x${publicKeyBytes[0].toString(16)}`);
      }
      return ec.keyFromPublic(publicKeyBytes);
      
    case 64:
      // Raw format: X + Y (add 0x04 prefix)
      const uncompressed = Buffer.concat([Buffer.from([0x04]), publicKeyBytes]);
      return ec.keyFromPublic(uncompressed);
      
    default:
      throw new Error(`Unsupported secp256r1 public key format: length ${publicKeyBytes.length}`);
  }
}