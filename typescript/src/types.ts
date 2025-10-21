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

export interface NodeConfig {
  nodeId: number;
  rpcAddress: string;
  cert: Buffer;
  key: Buffer;
  targetCert: Buffer;
  appNodeAddr: string;
  appNodeCert: Buffer;
}

export interface ClientOptions {
  configServerAddress?: string;
  cacheTTL?: number;           // Cache TTL in milliseconds
  maxConcurrentVotes?: number; // Max concurrent voting requests
  frostTimeout?: number;       // Timeout for FROST operations (ms)
  ecdsaTimeout?: number;       // Timeout for ECDSA operations (ms)
  timeout?: number;            // General timeout (deprecated, use frostTimeout)
}

// SignOptions for v3.0 API (simplified - removed appID, enableVoting, voteRequestData, headers)
export interface SignOptions {
  localApproval?: boolean;   // Local approval status for voting
  httpRequest?: any;         // Original HTTP request (for voting)
}

// SignRequest - DEPRECATED in v3.0, kept for backward compatibility
// Use Sign(message, options?) instead
export interface SignRequest {
  message: Uint8Array;      // Message to sign
  appID: string;            // App ID for signing
  enableVoting?: boolean;    // Whether to enable voting process

  // Voting-specific fields (only used when enableVoting is true)
  localApproval?: boolean;   // Local approval status for voting
  voteRequestData?: Uint8Array; // Vote request body data
  headers?: { [key: string]: string }; // HTTP headers to forward
  httpRequest?: any;        // Original HTTP request (optional)
}

// SignResult matches Go's SignResult struct
export interface SignResult {
  signature?: Uint8Array;   // Signature bytes
  success: boolean;         // Success status
  error?: string;          // Error message if any
  
  // Voting-specific fields (only present when voting was performed)
  votingInfo?: VotingInfo;
}

// VotingInfo matches Go's VotingInfo struct
export interface VotingInfo {
  totalTargets: number;
  successfulVotes: number;
  requiredVotes: number;
  voteDetails: VoteDetail[];
}

// Old interfaces kept for backward compatibility
export interface SignResponse {
  success: boolean;
  error?: string;
  signature?: Uint8Array;
}

export const Protocol = {
  ECDSA: 1,
  SCHNORR: 2,
} as const;

export const Curve = {
  ED25519: 1,
  SECP256K1: 2,
  SECP256R1: 3,
} as const;

export const NodeType = {
  INVALID_NODE: 0,
  TEE_NODE: 1,
  MESH_NODE: 2,
  APP_NODE: 3,
} as const;

// VoteDetail contains details of each vote
export interface VoteDetail {
  clientId: string;
  success: boolean;
  response: boolean;
  error?: string;
}

// VotingResult contains the result of a voting process
export interface VotingResult {
  totalTargets: number;
  successfulVotes: number;
  requiredVotes: number;
  votingComplete: boolean;
  finalResult: string;
  voteDetails: VoteDetail[];
  signature?: Uint8Array;
}

// VotingRequest for voting system
export interface VotingRequest {
  task_id: string;
  message: Uint8Array;
  required_votes: number;
  total_participants: number;
  app_id?: string;
  target_container_ip?: string;
}

// VotingResponse for voting system
export interface VotingResponse {
  success: boolean;
  task_id: string;
  error?: string;
}

// Voting handler function type
export type VotingHandler = (request: VotingRequest) => Promise<VotingResponse>;

// Deployment target information
export interface DeploymentTarget {
  appID: string;
  address: string;
  port: number;
  containerIP: string;
  deploymentClientAddress: string;  // gRPC deployment client address
  votingSignPath: string;           // HTTP API path for VotingSign requests
  httpBaseURL: string;              // HTTP base URL for API forwarding
  servicePort?: number;             // Container service port
  authHeaders?: { [key: string]: string }; // Optional authentication headers
}

export const Constants = {
  DEFAULT_CLIENT_TIMEOUT: 30000,
  DEFAULT_CONFIG_TIMEOUT: 10000,
  DEFAULT_TASK_TIMEOUT: 30000,
  DEFAULT_VOTING_PORT: 50053,
} as const;