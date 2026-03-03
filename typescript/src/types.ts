// -----------------------------------------------------------------------------
// Copyright (c) 2025 TEENet Technology (Hong Kong) Limited.
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

/**
 * Protocol constants for signature algorithms
 */
export const Protocol = {
  ECDSA: 'ecdsa',
  Schnorr: 'schnorr',
} as const;

export type ProtocolType = (typeof Protocol)[keyof typeof Protocol];

/**
 * Curve constants for elliptic curves
 */
export const Curve = {
  ED25519: 'ed25519',
  SECP256K1: 'secp256k1',
  SECP256R1: 'secp256r1',
} as const;

export type CurveType = (typeof Curve)[keyof typeof Curve];

/**
 * Client configuration options
 */
export interface ClientOptions {
  /** Request timeout in milliseconds (default: 30000) */
  requestTimeout?: number;
  /** Max wait in sign() when voting is pending (default: 10000) */
  pendingWaitTimeout?: number;
  /** Enable verbose sign/polling debug logs (default: false) */
  debug?: boolean;
}

export const ErrorCode = {
  INVALID_INPUT: 'INVALID_INPUT',
  SIGN_REQUEST_FAILED: 'SIGN_REQUEST_FAILED',
  SIGN_REQUEST_REJECTED: 'SIGN_REQUEST_REJECTED',
  SIGNATURE_DECODE_FAILED: 'SIGNATURE_DECODE_FAILED',
  UNEXPECTED_STATUS: 'UNEXPECTED_STATUS',
  MISSING_HASH: 'MISSING_HASH',
  STATUS_QUERY_FAILED: 'STATUS_QUERY_FAILED',
  THRESHOLD_TIMEOUT: 'THRESHOLD_TIMEOUT',
  SIGN_FAILED: 'SIGN_FAILED',
} as const;

export type ErrorCodeType = (typeof ErrorCode)[keyof typeof ErrorCode];

/**
 * Result of a signing operation
 */
export interface SignResult {
  /** Whether signing completed successfully */
  success: boolean;
  /** The signature bytes as a Buffer */
  signature: Buffer;
  /** Error message if the operation failed */
  error?: string;
  /** Stable machine-readable error code if the operation failed */
  errorCode?: ErrorCodeType;
  /** Voting metadata when threshold signing is used */
  votingInfo?: VotingInfo;
}

/**
 * Voting metadata for threshold signing
 */
export interface VotingInfo {
  /** Whether voting is required */
  needsVoting: boolean;
  /** Current number of votes */
  currentVotes: number;
  /** Required votes to reach threshold */
  requiredVotes: number;
  /** Status: pending, signed, failed */
  status: string;
  /** Message hash */
  hash: string;
}

/**
 * Status of a voting request from consensus cache
 */
export interface VoteStatus {
  /** Whether entry was found */
  found: boolean;
  /** Message hash */
  hash: string;
  /** Status: pending, signed, failed */
  status: string;
  /** Current number of votes */
  currentVotes: number;
  /** Required votes */
  requiredVotes: number;
  /** Signature bytes if signed */
  signature?: Buffer;
  /** Error message if any */
  errorMessage?: string;
}

/**
 * Result of a passkey approval API operation
 */
export interface ApprovalResult {
  /** Whether HTTP status is 2xx */
  success: boolean;
  /** Raw HTTP status code */
  statusCode: number;
  /** Parsed JSON response body */
  data?: Record<string, unknown>;
  /** Error message if operation failed */
  error?: string;
}

/**
 * Provider used by high-level passkey helpers to obtain a WebAuthn credential.
 * The caller decides how to run WebAuthn (for example in browser via navigator.credentials.get).
 */
export type PasskeyCredentialProvider = (options: unknown) => Promise<unknown>;

/**
 * Public key information returned from key generation
 */
export interface PublicKeyInfo {
  /** Unique key ID */
  id: number;
  /** Key name */
  name: string;
  /** Hex-encoded public key data */
  keyData: string;
  /** Elliptic curve used */
  curve: string;
  /** Signing protocol */
  protocol: string;
  /** Threshold for multi-sig (optional) */
  threshold?: number;
  /** Number of participants (optional) */
  participantCount?: number;
  /** Maximum participant count (optional) */
  maxParticipantCount?: number;
  /** Application ID */
  applicationId: number;
  /** Instance ID that created this key */
  createdByInstanceId: string;
}

/**
 * Result of a key generation operation
 */
export interface GenerateKeyResult {
  /** Whether the operation succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Generated public key information */
  publicKey: PublicKeyInfo;
}

/**
 * Result of getting an API key
 */
export interface APIKeyResult {
  /** Whether the operation succeeded */
  success: boolean;
  /** The API key value */
  apiKey: string;
  /** Error message if the operation failed */
  error?: string;
}

/**
 * Result of signing with an API secret
 */
export interface APISignResult {
  /** Whether the operation succeeded */
  success: boolean;
  /** Hex-encoded signature */
  signature: string;
  /** Algorithm used (e.g., "HMAC-SHA256") */
  algorithm: string;
  /** Error message if the operation failed */
  error?: string;
}

/**
 * Public key information returned from getPublicKey
 */
export interface PublicKeyResponse {
  /** Hex-encoded public key */
  publicKey: string;
  /** Signing protocol */
  protocol: string;
  /** Elliptic curve */
  curve: string;
}
