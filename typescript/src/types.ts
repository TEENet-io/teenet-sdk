// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

/**
 * Protocol constants for signature algorithms
 */
export const Protocol = {
  ECDSA: 'ecdsa',
  Schnorr: 'schnorr',
  /**
   * Semantic alias for Schnorr+Ed25519. Use this with Curve.ED25519 in
   * generateKey() when you want RFC 8032 EdDSA naming. Rejected with any
   * other curve.
   */
  EdDSA: 'eddsa',
  /**
   * Semantic alias for Schnorr+secp256k1 matching BIP-340 (Bitcoin Taproot).
   * Use this with Curve.SECP256K1 in generateKey() when generating keys for
   * Bitcoin Taproot (P2TR) outputs. Rejected with any other curve.
   */
  SchnorrBIP340: 'schnorr-bip340',
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
  /** Key cache TTL in milliseconds (default: 60000). Set to -1 to disable caching. */
  keyCacheTTL?: number;
}

/**
 * Status constants for voting/approval flow
 */
export const Status = {
  PENDING: 'pending',
  SIGNED: 'signed',
  FAILED: 'failed',
  PENDING_APPROVAL: 'pending_approval',
} as const;

export type StatusType = (typeof Status)[keyof typeof Status];

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
  APPROVAL_PENDING: 'APPROVAL_PENDING',
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
  /** Transaction ID for approval flow */
  txID?: string;
  /** Request ID for approval flow */
  requestID?: number;
}

/**
 * Status of a voting request from service cache
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
 * Optional filters for approvalPending().
 */
export interface ApprovalPendingFilter {
  /** Filter by application ID */
  applicationId?: number;
  /** Filter by bound public key name (requires applicationId) */
  publicKeyName?: string;
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

// ─── Admin management types ──────────────────────────────────────────────────

/**
 * Request parameters for inviting a passkey user.
 */
export interface PasskeyInviteRequest {
  /** Human-readable name of the invited user */
  displayName: string;
  /** Optionally scope the user to a specific application */
  applicationId?: number;
  /** Invite link TTL in seconds (0 = server default) */
  expiresInSeconds?: number;
}

/**
 * Result of InvitePasskeyUser.
 */
export interface PasskeyInviteResult {
  success: boolean;
  error?: string;
  inviteToken?: string;
  registerUrl?: string;
  expiresAt?: string;
}

/**
 * A registered passkey user.
 */
export interface PasskeyUser {
  id: number;
  displayName: string;
  userHandle?: string;
  applicationId?: number;
  createdAt?: string;
}

/**
 * Result of ListPasskeyUsers.
 */
export interface PasskeyUsersResult {
  success: boolean;
  error?: string;
  users: PasskeyUser[];
  total: number;
  page: number;
  limit: number;
}

/**
 * A single audit log entry.
 */
export interface AuditRecord {
  id: number;
  taskId?: number;
  requestSessionId?: number;
  eventType?: string;
  action?: string;
  status?: string;
  actorPasskeyUserId?: number;
  actorDisplayName?: string;
  txId?: string;
  hash?: string;
  signature?: string;
  appInstanceId?: string;
  details?: string;
  errorMessage?: string;
  createdAt?: string;
}

/**
 * Result of ListAuditRecords.
 */
export interface AuditRecordsResult {
  success: boolean;
  error?: string;
  records: AuditRecord[];
  total: number;
  page: number;
  limit: number;
}

/**
 * One approval level in a permission policy.
 */
export interface PolicyLevel {
  levelIndex: number;
  threshold: number;
  memberIds: number[];
}

/**
 * Request parameters for UpsertPermissionPolicy.
 */
export interface PolicyRequest {
  /** Name of the public key this policy applies to */
  publicKeyName: string;
  /** Whether this policy is active */
  enabled: boolean;
  /** Approval window in seconds (0 = server default) */
  timeoutSeconds?: number;
  /** Ordered approval levels */
  levels: PolicyLevel[];
}

/**
 * A stored permission policy.
 */
export interface Policy {
  id: number;
  applicationId: number;
  publicKeyId: number;
  publicKeyName?: string;
  enabled: boolean;
  timeoutSeconds: number;
  levels?: PolicyLevel[];
}

/**
 * Result of GetPermissionPolicy.
 */
export interface PolicyResult {
  success: boolean;
  error?: string;
  policy?: Policy;
}

/**
 * Generic result for admin operations with no specific payload.
 */
export interface AdminResult {
  success: boolean;
  error?: string;
}

/**
 * Bound public key information for an application.
 */
export interface BoundPublicKeyInfo {
  /** Unique key ID */
  id: number;
  /** Key name */
  name: string;
  /** Hex-encoded public key data */
  keyData: string;
  /** Signing protocol */
  protocol: string;
  /** Elliptic curve */
  curve: string;
  /** Threshold for multi-sig */
  threshold?: number;
  /** Number of participants */
  participantCount?: number;
  /** Maximum participant count */
  maxParticipantCount?: number;
  /** Application ID */
  applicationId?: number;
  /** Instance ID that created this key */
  createdByInstanceId?: string;
}

/**
 * Request to create a new API key via admin bridge.
 */
export interface CreateAPIKeyRequest {
  /** Name of the API key */
  name: string;
  /** Optional human-readable description */
  description?: string;
  /** The API key value to store */
  apiKey?: string;
  /** The API secret to store */
  apiSecret?: string;
}

/**
 * Result of creating an API key.
 */
export interface CreateAPIKeyResult {
  success: boolean;
  error?: string;
  id?: number;
  name?: string;
  hasApiKey?: boolean;
  hasApiSecret?: boolean;
}

/**
 * Result of passkey registration options request.
 */
export interface PasskeyRegistrationOptionsResult {
  success: boolean;
  error?: string;
  inviteToken?: string;
  options?: unknown;
  expiresAt?: string;
}

/**
 * Result of passkey registration verification.
 */
export interface PasskeyRegistrationVerifyResult {
  success: boolean;
  error?: string;
  passkeyUserId?: number;
  displayName?: string;
}
