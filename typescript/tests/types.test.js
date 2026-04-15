// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Tests for exported constants in types.ts — ErrorCode, Protocol, Curve, Status.
//
// Run via: npm test  (build + node --test tests)

'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const { ErrorCode, Protocol, Curve, Status } = require('../dist/index.js');

// ─── ErrorCode ────────────────────────────────────────────────────────────────

test('ErrorCode.INVALID_INPUT is the string literal "INVALID_INPUT"', () => {
  assert.equal(ErrorCode.INVALID_INPUT, 'INVALID_INPUT');
});

test('ErrorCode.SIGN_REQUEST_FAILED is defined', () => {
  assert.equal(ErrorCode.SIGN_REQUEST_FAILED, 'SIGN_REQUEST_FAILED');
});

test('ErrorCode.SIGN_REQUEST_REJECTED is defined', () => {
  assert.equal(ErrorCode.SIGN_REQUEST_REJECTED, 'SIGN_REQUEST_REJECTED');
});

test('ErrorCode.SIGNATURE_DECODE_FAILED is defined', () => {
  assert.equal(ErrorCode.SIGNATURE_DECODE_FAILED, 'SIGNATURE_DECODE_FAILED');
});

test('ErrorCode.UNEXPECTED_STATUS is defined', () => {
  assert.equal(ErrorCode.UNEXPECTED_STATUS, 'UNEXPECTED_STATUS');
});

test('ErrorCode.MISSING_HASH is defined', () => {
  assert.equal(ErrorCode.MISSING_HASH, 'MISSING_HASH');
});

test('ErrorCode.STATUS_QUERY_FAILED is defined', () => {
  assert.equal(ErrorCode.STATUS_QUERY_FAILED, 'STATUS_QUERY_FAILED');
});

test('ErrorCode.SIGN_FAILED is defined', () => {
  assert.equal(ErrorCode.SIGN_FAILED, 'SIGN_FAILED');
});

test('ErrorCode.THRESHOLD_TIMEOUT is defined', () => {
  assert.equal(ErrorCode.THRESHOLD_TIMEOUT, 'THRESHOLD_TIMEOUT');
});

test('ErrorCode.APPROVAL_PENDING is defined', () => {
  assert.equal(ErrorCode.APPROVAL_PENDING, 'APPROVAL_PENDING');
});

test('ErrorCode has exactly 10 entries', () => {
  assert.equal(Object.keys(ErrorCode).length, 10);
});

test('ErrorCode values are all unique strings', () => {
  const values = Object.values(ErrorCode);
  const unique = new Set(values);
  assert.equal(unique.size, values.length);
});

// ─── Protocol ─────────────────────────────────────────────────────────────────

test('Protocol.ECDSA is "ecdsa"', () => {
  assert.equal(Protocol.ECDSA, 'ecdsa');
});

test('Protocol.Schnorr is "schnorr"', () => {
  assert.equal(Protocol.Schnorr, 'schnorr');
});

test('Protocol.EdDSA is "eddsa"', () => {
  assert.equal(Protocol.EdDSA, 'eddsa');
});

test('Protocol.SchnorrBIP340 is "schnorr-bip340"', () => {
  assert.equal(Protocol.SchnorrBIP340, 'schnorr-bip340');
});

test('Protocol has exactly 4 entries', () => {
  assert.equal(Object.keys(Protocol).length, 4);
});

// ─── Curve ────────────────────────────────────────────────────────────────────

test('Curve.ED25519 is "ed25519"', () => {
  assert.equal(Curve.ED25519, 'ed25519');
});

test('Curve.SECP256K1 is "secp256k1"', () => {
  assert.equal(Curve.SECP256K1, 'secp256k1');
});

test('Curve.SECP256R1 is "secp256r1"', () => {
  assert.equal(Curve.SECP256R1, 'secp256r1');
});

test('Curve has exactly 3 entries', () => {
  assert.equal(Object.keys(Curve).length, 3);
});

// ─── Status ───────────────────────────────────────────────────────────────────

test('Status.PENDING is "pending"', () => {
  assert.equal(Status.PENDING, 'pending');
});

test('Status.SIGNED is "signed"', () => {
  assert.equal(Status.SIGNED, 'signed');
});

test('Status.FAILED is "failed"', () => {
  assert.equal(Status.FAILED, 'failed');
});

test('Status.PENDING_APPROVAL is "pending_approval"', () => {
  assert.equal(Status.PENDING_APPROVAL, 'pending_approval');
});

test('Status has exactly 4 entries', () => {
  assert.equal(Object.keys(Status).length, 4);
});

// ─── Cross-consistency checks ─────────────────────────────────────────────────

test('Status.PENDING_APPROVAL matches ErrorCode.APPROVAL_PENDING concept', () => {
  // Status describes server state; ErrorCode describes SDK-level error.
  // They are related but use different naming conventions — confirm both exist.
  assert.ok(Status.PENDING_APPROVAL, 'Status.PENDING_APPROVAL should be truthy');
  assert.ok(ErrorCode.APPROVAL_PENDING, 'ErrorCode.APPROVAL_PENDING should be truthy');
});

test('all Curve values are lowercase strings', () => {
  for (const [key, val] of Object.entries(Curve)) {
    assert.equal(typeof val, 'string', `Curve.${key} should be a string`);
    assert.equal(val, val.toLowerCase(), `Curve.${key} should be lowercase`);
  }
});

test('all Protocol values are lowercase strings', () => {
  for (const [key, val] of Object.entries(Protocol)) {
    assert.equal(typeof val, 'string', `Protocol.${key} should be a string`);
    assert.equal(val, val.toLowerCase(), `Protocol.${key} should be lowercase`);
  }
});

test('all Status values are lowercase strings', () => {
  for (const [key, val] of Object.entries(Status)) {
    assert.equal(typeof val, 'string', `Status.${key} should be a string`);
    assert.equal(val, val.toLowerCase(), `Status.${key} should be lowercase`);
  }
});
