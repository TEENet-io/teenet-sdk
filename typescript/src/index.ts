// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

export { Client } from './client';
export {
  Protocol,
  Curve,
  ClientOptions,
  SignResult,
  VotingInfo,
  VoteStatus,
  ApprovalResult,
  ApprovalPendingFilter,
  PasskeyCredentialProvider,
  GenerateKeyResult,
  PublicKeyInfo,
  APIKeyResult,
  APISignResult,
  BoundPublicKeyInfo,
  ProtocolType,
  CurveType,
  ErrorCode,
  ErrorCodeType,
  PasskeyInviteRequest,
  PasskeyInviteResult,
  PasskeyUser,
  PasskeyUsersResult,
  AuditRecord,
  AuditRecordsResult,
  PolicyLevel,
  PolicyRequest,
  Policy,
  PolicyResult,
  AdminResult,
  CreateAPIKeyRequest,
  CreateAPIKeyResult,
  PasskeyRegistrationOptionsResult,
  PasskeyRegistrationVerifyResult,
  Status,
  StatusType,
} from './types';
export { verifySignature, verifyHMACSHA256 } from './crypto';
