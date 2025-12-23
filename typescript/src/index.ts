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
//
// TEENet SDK for TypeScript/JavaScript
//
// This SDK enables applications to request cryptographic signatures from TEENet's
// Trusted Execution Environment (TEE) consensus nodes.
//
// -----------------------------------------------------------------------------

export { Client } from './client';
export {
  Protocol,
  Curve,
  ClientOptions,
  SignResult,
  GenerateKeyResult,
  PublicKeyInfo,
  APIKeyResult,
  APISignResult,
  PublicKeyResponse,
  ProtocolType,
  CurveType,
} from './types';
export { verifySignature, verifyHMACSHA256 } from './crypto';
