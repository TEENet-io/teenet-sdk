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

import { NodeConfig, ClientOptions, Constants, Protocol, Curve, VotingResult, VoteDetail, VotingRequest, VotingResponse, SignRequest, SignResult, VotingInfo, SignOptions } from './types';
import { ConfigClient } from './config-client';
import { TaskClient } from './task-client';
import { AppIDClient } from './appid-client';
import { VotingClient } from './voting-client';
import { verifySignature } from './verification';
import * as tls from 'tls';
import { IncomingMessage } from 'http';

export class Client {
  private configClient: ConfigClient;
  private taskClient: TaskClient | null = null;
  private appIDClient: AppIDClient | null = null;
  private nodeConfig: NodeConfig | null = null;
  private frostTimeout: number;
  private ecdsaTimeout: number;

  // Default App ID (optional, can be set from environment variable)
  public defaultAppID: string = '';

  // Caching
  private publicKeyCache: Map<string, { publicKey: string; protocol: string; curve: string; timestamp: number }> = new Map();
  private deploymentCache: Map<string, { targets: any; votingPath: string; requiredVotes: number; enableVotingSign: boolean; timestamp: number }> = new Map();
  private cacheTTL: number;
  private cleanupInterval: NodeJS.Timeout | null = null;

  // Concurrency control
  private maxConcurrentVotes: number;

  constructor(options?: Partial<ClientOptions>) {
    // Read config server address from environment variable or use default
    const configServerAddress = process.env.TEE_CONFIG_ADDR || 'localhost:50052';

    this.configClient = new ConfigClient(configServerAddress);
    this.frostTimeout = options?.frostTimeout || options?.timeout || Constants.DEFAULT_CLIENT_TIMEOUT;
    this.ecdsaTimeout = options?.ecdsaTimeout || this.frostTimeout * 2;
    this.cacheTTL = options?.cacheTTL || 5 * 60 * 1000; // Default 5 minutes
    this.maxConcurrentVotes = options?.maxConcurrentVotes || 10;
  }

  // Set default App ID
  setDefaultAppID(appID: string): void {
    this.defaultAppID = appID;
  }

  // Set default App ID from environment variable
  setDefaultAppIDFromEnv(): void {
    const appID = process.env.APP_ID;
    if (appID) {
      this.defaultAppID = appID;
    }
  }

  async init(): Promise<void> {
    // 1. Fetch configuration
    const nodeConfig = await this.configClient.getConfig(this.frostTimeout);
    this.nodeConfig = nodeConfig;

    // 2. Create task client
    this.taskClient = new TaskClient(nodeConfig);

    // 3. Connect to TEE server
    await this.taskClient.connect(this.frostTimeout);

    // 4. Create AppID client
    this.appIDClient = new AppIDClient(nodeConfig.appNodeAddr);

    // 5. Create TLS configuration for App node
    const appTLSConfig = this.createAppTLSConfig();

    // 6. Connect to user management system
    await this.appIDClient.connect(appTLSConfig);

    // 7. Initialize default App ID from environment variable if set
    if (process.env.APP_ID && !this.defaultAppID) {
      this.setDefaultAppID(process.env.APP_ID);
      console.log(`🔑 Default App ID initialized from environment: ${this.defaultAppID}`);
    }

    // 8. Start cache cleanup timer
    this.startCacheCleanup();

    console.log(`✅ Client initialized successfully, node ID: ${nodeConfig.nodeId}`);
  }

  private startCacheCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();

      // Clean expired public key cache entries
      for (const [key, value] of this.publicKeyCache.entries()) {
        if (now - value.timestamp > this.cacheTTL) {
          this.publicKeyCache.delete(key);
        }
      }

      // Clean expired deployment cache entries
      for (const [key, value] of this.deploymentCache.entries()) {
        if (now - value.timestamp > this.cacheTTL) {
          this.deploymentCache.delete(key);
        }
      }
    }, 60000); // Run every minute
  }

  async close(): Promise<void> {
    // Stop cache cleanup timer
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    // Close clients
    if (this.taskClient) {
      await this.taskClient.close();
      this.taskClient = null;
    }
    if (this.appIDClient) {
      this.appIDClient.close();
      this.appIDClient = null;
    }

    console.log('✅ All clients closed');
  }


  getNodeId(): number {
    if (!this.nodeConfig) {
      return 0;
    }
    return this.nodeConfig.nodeId;
  }

  setTimeout(timeout: number): void {
    this.frostTimeout = timeout;
    this.ecdsaTimeout = timeout * 2;
  }

  setTaskTimeout(timeout: number): void {
    this.setTimeout(timeout);
  }

  // Create TLS configuration for App node (user management system)
  private createAppTLSConfig(): tls.SecureContextOptions {
    if (!this.nodeConfig) {
      throw new Error('config not loaded');
    }
    return {
      cert: this.nodeConfig.cert,
      key: this.nodeConfig.key,
      ca: this.nodeConfig.appNodeCert,
    };
  }

  // Get public key using default App ID (v3.0 API)
  async getPublicKey(): Promise<{publickey: string, protocol: string, curve: string}> {
    if (!this.defaultAppID) {
      throw new Error('default App ID is not set');
    }
    return this.getPublicKeyInfo(this.defaultAppID);
  }

  // Get public key by app ID from user management system (kept for backward compatibility)
  async getPublicKeyByAppID(appId: string): Promise<{publickey: string, protocol: string, curve: string}> {
    return this.getPublicKeyInfo(appId);
  }

  // Internal method to get public key with caching
  private async getPublicKeyInfo(appId: string): Promise<{publickey: string, protocol: string, curve: string}> {
    if (!this.appIDClient) {
      throw new Error('AppID client not initialized');
    }

    // Check cache first
    const cached = this.publicKeyCache.get(appId);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return {
        publickey: cached.publicKey,
        protocol: cached.protocol,
        curve: cached.curve
      };
    }

    // Fetch from server
    const result = await this.appIDClient.getPublicKeyByAppID(appId);

    // Update cache
    this.publicKeyCache.set(appId, {
      publicKey: result.publickey,
      protocol: result.protocol,
      curve: result.curve,
      timestamp: Date.now()
    });

    return result;
  }


  // Parse protocol string to number
  private parseProtocol(protocol: string): number {
    switch (protocol) {
      case 'schnorr':
        return Protocol.SCHNORR;
      case 'ecdsa':
        return Protocol.ECDSA;
      default:
        const num = parseInt(protocol, 10);
        return isNaN(num) ? Protocol.SCHNORR : num; // Default to schnorr
    }
  }

  // Parse curve string to number
  private parseCurve(curve: string): number {
    switch (curve) {
      case 'ed25519':
        return Curve.ED25519;
      case 'secp256k1':
        return Curve.SECP256K1;
      case 'secp256r1':
        return Curve.SECP256R1;
      default:
        const num = parseInt(curve, 10);
        return isNaN(num) ? Curve.ED25519 : num; // Default to ed25519
    }
  }

  // Sign with AppID (internal method)
  private async signWithAppID(message: Uint8Array, appId: string): Promise<Uint8Array> {
    if (!this.taskClient) {
      throw new Error('client not initialized');
    }

    // Get public key from user management system
    const { publickey, protocol, curve } = await this.getPublicKeyInfo(appId);

    // Parse protocol and curve
    const protocolNum = this.parseProtocol(protocol);
    const curveNum = this.parseCurve(curve);

    // Decode public key from hex (remove 0x prefix if present)
    const publicKeyHex = publickey.startsWith('0x') || publickey.startsWith('0X')
      ? publickey.slice(2)
      : publickey;
    const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');

    // Sign the message directly through taskClient
    const timeout = protocolNum === Protocol.ECDSA ? this.ecdsaTimeout : this.frostTimeout;
    return this.taskClient.sign(message, new Uint8Array(publicKeyBuffer), protocolNum, curveNum, timeout);
  }

  // Get deployment targets with caching
  private async getDeploymentTargets(appId: string): Promise<{ targets: any; votingPath: string; requiredVotes: number; enableVotingSign: boolean }> {
    if (!this.appIDClient) {
      throw new Error('AppID client not initialized');
    }

    // Check cache first
    const cached = this.deploymentCache.get(appId);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return {
        targets: cached.targets,
        votingPath: cached.votingPath,
        requiredVotes: cached.requiredVotes,
        enableVotingSign: cached.enableVotingSign
      };
    }

    // Fetch from server
    const result = await this.appIDClient.getDeploymentTargetsForVotingSign(appId, this.frostTimeout);

    // Check if voting is enabled based on deployment targets
    const enableVotingSign = Object.keys(result.deploymentTargets).length > 0 && result.requiredVotes > 0;

    // Update cache
    this.deploymentCache.set(appId, {
      targets: result.deploymentTargets,
      votingPath: result.votingSignPath,
      requiredVotes: result.requiredVotes,
      enableVotingSign: enableVotingSign,
      timestamp: Date.now()
    });

    return {
      targets: result.deploymentTargets,
      votingPath: result.votingSignPath,
      requiredVotes: result.requiredVotes,
      enableVotingSign: enableVotingSign
    };
  }

  // Sign method - v3.0 API
  async sign(message: Uint8Array, options?: SignOptions): Promise<SignResult> {
    if (!this.defaultAppID) {
      throw new Error('default App ID is not set');
    }

    const appID = this.defaultAppID;
    const opt = options || {};

    // Check if voting is enabled for this AppID
    const { targets, votingPath, requiredVotes, enableVotingSign } = await this.getDeploymentTargets(appID);

    // If voting is not enabled, perform regular signing
    if (!enableVotingSign) {
      try {
        const signature = await this.signWithAppID(message, appID);
        return {
          signature,
          success: true
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message || 'signing failed'
        };
      }
    }

    // Voting is enabled, perform voting sign
    try {
      let voteRequestData: Uint8Array | undefined;
      let headers: { [key: string]: string } | undefined;

      // Extract headers and request body from HTTP request if provided
      if (opt.httpRequest) {
        headers = this.extractHeadersFromRequest(opt.httpRequest);

        // Read request body if available
        if ((opt.httpRequest as any).body) {
          const bodyStr = typeof (opt.httpRequest as any).body === 'string'
            ? (opt.httpRequest as any).body
            : JSON.stringify((opt.httpRequest as any).body);
          voteRequestData = new TextEncoder().encode(bodyStr);
        }
      }

      const votingResult = await this.votingSignWithHeaders(
        message,
        appID,
        opt.localApproval || false,
        voteRequestData,
        headers
      );

      // Convert VotingResult to SignResult
      const result: SignResult = {
        signature: votingResult.signature,
        success: votingResult.votingComplete && votingResult.signature !== undefined,
        votingInfo: {
          totalTargets: votingResult.totalTargets,
          successfulVotes: votingResult.successfulVotes,
          requiredVotes: votingResult.requiredVotes,
          voteDetails: votingResult.voteDetails
        }
      };

      if (!result.success) {
        result.error = votingResult.finalResult;
      }

      return result;
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'voting sign failed'
      };
    }
  }

  // VotingSign performs a voting process for the specified app ID using HTTP requests and returns detailed results with signature if approved
  // The target app IDs and required votes are fetched from the server based on the VotingSign project configuration
  async votingSign(
    req: IncomingMessage | null,
    message: Uint8Array,
    signerAppId: string,
    localApproval: boolean
  ): Promise<VotingResult> {
    let voteRequestData: Uint8Array | undefined;
    let headers: { [key: string]: string } | undefined;

    // Extract headers and request body from HTTP request if provided
    if (req) {
      headers = this.extractHeadersFromRequest(req);
      
      // Read request body if available
      if ((req as any).body) {
        const bodyStr = typeof (req as any).body === 'string' ? (req as any).body : JSON.stringify((req as any).body);
        voteRequestData = new TextEncoder().encode(bodyStr);
      }
    }
    
    return this.votingSignWithHeaders(message, signerAppId, localApproval, voteRequestData, headers);
  }

  // VotingSignWithHeaders performs voting with custom headers forwarded to remote targets
  async votingSignWithHeaders(
    message: Uint8Array,
    signerAppId: string,
    localApproval: boolean,
    voteRequestData?: Uint8Array,
    headers?: { [key: string]: string }
  ): Promise<VotingResult> {
    // Parse isForwarded from the request data
    let isForwarded = false;
    if (voteRequestData) {
      try {
        const requestMap = JSON.parse(new TextDecoder().decode(voteRequestData));
        isForwarded = requestMap.is_forwarded || false;
      } catch (error) {
        // Ignore JSON parse errors
      }
    }

    // If this is a forwarded request, just return the local decision without further forwarding
    if (isForwarded) {
      console.log(`🔄 Forwarded request - returning local decision: ${localApproval} for app ${signerAppId}`);

      const result: VotingResult = {
        totalTargets: 1,
        successfulVotes: localApproval ? 1 : 0,
        requiredVotes: 1, // For forwarded requests, we don't know the actual required votes
        votingComplete: localApproval,
        finalResult: localApproval ? 'APPROVED' : 'REJECTED',
        voteDetails: [{ clientId: signerAppId, success: true, response: localApproval }]
      };

      return result;
    }

    // Get deployment targets, voting sign path, and required votes from server
    const { deploymentTargets, votingSignPath, requiredVotes } = await this.appIDClient!.getDeploymentTargetsForVotingSign(signerAppId, this.frostTimeout);
    
    // Extract target app IDs from deployment targets
    const targetAppIds = Object.keys(deploymentTargets);
    
    if (targetAppIds.length === 0) {
      throw new Error('no target app IDs configured for voting sign');
    }

    if (requiredVotes <= 0 || requiredVotes > targetAppIds.length) {
      throw new Error(`invalid required votes: ${requiredVotes} (should be 1-${targetAppIds.length})`);
    }

    if (!this.appIDClient) {
      throw new Error('AppID client not initialized');
    }

    console.log(`🗳️  Starting HTTP voting process for ${signerAppId}`);
    console.log(`👥 Targets: ${JSON.stringify(targetAppIds)}, required votes: ${requiredVotes}/${targetAppIds.length}`);

    // Initialize vote details and approval count
    const voteDetails: VoteDetail[] = [];
    let approvalCount = 0;
    
    // Add local vote only if signerAppId is in targetAppIds
    const signerInTargets = targetAppIds.includes(signerAppId);
    if (signerInTargets) {
      voteDetails.push({ clientId: signerAppId, success: true, response: localApproval });
      if (localApproval) {
        approvalCount = 1;
      }
    }

    // Batch get deployment targets for remote app IDs (excluding self)
    const remoteTargetAppIds = targetAppIds.filter(targetAppId => targetAppId !== signerAppId);

    // If there are remote targets, send voting requests
    if (remoteTargetAppIds.length > 0) {
      console.log(`🔍 Using deployment targets for remote apps: ${JSON.stringify(remoteTargetAppIds)}`);
      console.log(`📝 VotingSign path: ${votingSignPath}`);
      console.log(`✅ Found ${Object.keys(deploymentTargets).length} deployment targets: ${JSON.stringify(Object.keys(deploymentTargets))}`);

        // Send HTTP voting requests to remote targets concurrently
        const votePromises = remoteTargetAppIds.map(async (targetAppId): Promise<VoteDetail> => {
          const target = deploymentTargets[targetAppId];
          if (!target) {
            console.log(`❌ No deployment target found for ${targetAppId}, skipping`);
            return {
              clientId: targetAppId,
              success: false,
              response: false,
              error: 'No deployment target found'
            };
          }

          try {
            // Modify request body to mark as forwarded
            let modifiedRequestData = voteRequestData;
            if (voteRequestData) {
              modifiedRequestData = VotingClient.markRequestAsForwarded(voteRequestData);
            }

            const approved = await VotingClient.sendHTTPVoteRequestWithHeaders(target, modifiedRequestData || new Uint8Array(), headers || null, this.frostTimeout);

            return {
              clientId: targetAppId,
              success: true,
              response: approved,
            };
          } catch (error) {
            console.log(`❌ Failed to get vote from ${targetAppId}: ${error}`);
            return {
              clientId: targetAppId,
              success: false,
              response: false,
              error: error instanceof Error ? error.message : String(error)
            };
          }
        });

        // Collect remote voting results
        const remoteVoteDetails = await Promise.all(votePromises);
        voteDetails.push(...remoteVoteDetails);

        // Count additional approvals from remote votes
        for (const detail of remoteVoteDetails) {
          if (detail.success && detail.response) {
            approvalCount++;
            console.log(`✅ Vote approved by ${detail.clientId} (${approvalCount}/${requiredVotes})`);
          } else if (detail.success && !detail.response) {
            console.log(`❌ Vote rejected by ${detail.clientId}`);
          } else {
            console.log(`❌ Failed to get vote from ${detail.clientId}: ${detail.error}`);
          }
        }
    }

    // Create final voting result
    const votingResult: VotingResult = {
      totalTargets: targetAppIds.length,
      successfulVotes: approvalCount,
      requiredVotes,
      votingComplete: true,
      finalResult: '',
      voteDetails
    };

    // Check if voting passed
    if (approvalCount < requiredVotes) {
      votingResult.finalResult = 'REJECTED';
      console.log(`❌ Voting failed: only ${approvalCount}/${requiredVotes} approvals received`);
      return votingResult; // Don't throw error, just return result
    }

    // Generate signature
    console.log(`🔐 Generating signature for approved message (${approvalCount}/${requiredVotes} votes received)`);
    try {
      const signature = await this.signWithAppID(message, signerAppId);
      votingResult.finalResult = 'APPROVED';
      votingResult.signature = signature;
    } catch (error) {
      votingResult.finalResult = 'SIGNATURE_FAILED';
      throw new Error(`failed to generate signature: ${error}`);
    }

    console.log('✅ Voting and signing completed successfully');
    return votingResult;
  }

  // Helper method to extract headers from HTTP request - delegates to VotingClient
  private extractHeadersFromRequest(req: IncomingMessage): { [key: string]: string } {
    return VotingClient.extractHeadersFromRequest(req);
  }

  /**
   * Verifies a signature against a message using the public key associated with the default app ID (v3.0 API)
   * @param message - The original message that was signed
   * @param signature - The signature to verify
   * @returns true if the signature is valid, false otherwise
   */
  async verify(message: Buffer, signature: Buffer): Promise<boolean> {
    if (!this.defaultAppID) {
      throw new Error('default App ID is not set');
    }
    return this.verifyWithAppID(message, signature, this.defaultAppID);
  }

  /**
   * Verifies a signature against a message using the public key associated with the given app ID
   * (kept for backward compatibility)
   * @param message - The original message that was signed
   * @param signature - The signature to verify
   * @param appID - The app ID whose public key will be used for verification
   * @returns true if the signature is valid, false otherwise
   */
  async verifyWithAppID(message: Buffer, signature: Buffer, appID: string): Promise<boolean> {
    if (!this.appIDClient) {
      throw new Error('Client not initialized');
    }

    try {
      // Get public key from user management system
      const { publickey, protocol, curve } = await this.getPublicKeyInfo(appID);

      // Parse protocol and curve
      const protocolNum = this.parseProtocol(protocol);
      const curveNum = this.parseCurve(curve);

      // Decode public key from hex (remove 0x prefix if present)
      const publicKeyHex = publickey.startsWith('0x') || publickey.startsWith('0X')
        ? publickey.slice(2)
        : publickey;
      const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');

      // Verify the signature using the verification module
      return await verifySignature(
        message,
        publicKeyBuffer,
        signature,
        protocolNum as typeof Protocol[keyof typeof Protocol],
        curveNum as typeof Curve[keyof typeof Curve]
      );
    } catch (error) {
      console.error(`Failed to verify signature: ${error}`);
      return false;
    }
  }
}