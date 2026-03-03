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

import {
  ClientOptions,
  SignResult,
  VotingInfo,
  VoteStatus,
  ApprovalResult,
  PasskeyCredentialProvider,
  GenerateKeyResult,
  APIKeyResult,
  APISignResult,
  PublicKeyResponse,
  Protocol,
  PublicKeyInfo,
  ErrorCode,
  ErrorCodeType,
} from './types';
import { verifySignature } from './crypto';
import { sha256 } from '@noble/hashes/sha256';

const DEFAULT_REQUEST_TIMEOUT = 30000;
const DEFAULT_PENDING_WAIT_TIMEOUT = 10 * 1000;
const DEFAULT_STATUS_POLL_INTERVAL = 1000;
const MAX_STATUS_POLL_INTERVAL = 5000;

interface APIResponse {
  success: boolean;
  message?: string;
  error?: string;
  signature?: string;
  hash?: string;
  status?: string;
  current_votes?: number;
  required_votes?: number;
  needs_voting?: boolean;
  public_key?: string | APIPublicKeyInfo;
  protocol?: string;
  curve?: string;
  api_key?: string;
  algorithm?: string;
}

interface APIPublicKeyInfo {
  id: number;
  name: string;
  key_data: string;
  curve: string;
  protocol: string;
  threshold?: number;
  participant_count?: number;
  max_participant_count?: number;
  application_id: number;
  created_by_instance_id: string;
}

interface CacheDetailResponse {
  success: boolean;
  found: boolean;
  entry?: CacheEntry;
  message?: string;
}

interface CacheEntry {
  hash: string;
  status: string;
  signature?: string;
  required_votes: number;
  requests?: Record<string, CacheRequest>;
  error_message?: string;
}

interface CacheRequest {
  approved: boolean;
}

/**
 * TEENet SDK Client
 *
 * Provides cryptographic signing services via TEE consensus nodes.
 *
 * @example
 * ```typescript
 * const client = new Client('http://localhost:8089');
 * client.setDefaultAppID('your-app-id');
 *
 * // Sign a message
 * const result = await client.sign(Buffer.from('message'));
 * if (result.success) {
 *   console.log('Signature:', result.signature.toString('hex'));
 * }
 *
 * // Verify a signature
 * const valid = await client.verify(message, result.signature);
 * ```
 */
export class Client {
  private consensusURL: string;
  private defaultAppID: string = '';
  private requestTimeout: number;
  private pendingWaitTimeout: number;
  private debug: boolean;

  /**
   * Create a new TEENet SDK client
   * @param consensusURL - Base URL of the consensus service
   * @param options - Optional configuration
   */
  constructor(consensusURL: string, options?: ClientOptions) {
    this.consensusURL = consensusURL.replace(/\/$/, ''); // Remove trailing slash
    this.requestTimeout = options?.requestTimeout ?? DEFAULT_REQUEST_TIMEOUT;
    this.pendingWaitTimeout = Math.max(options?.pendingWaitTimeout ?? DEFAULT_PENDING_WAIT_TIMEOUT, 0);
    this.debug = Boolean(options?.debug);
  }

  /**
   * Initialize client from environment variables
   * Reads APP_INSTANCE_ID and sets it as the default App ID
   */
  init(): void {
    const appID = process.env.APP_INSTANCE_ID;
    if (appID) {
      this.defaultAppID = appID;
    } else {
      console.warn('APP_INSTANCE_ID environment variable not set');
    }
  }

  /**
   * Set the default application ID
   * @param appID - Your TEENet application ID
   */
  setDefaultAppID(appID: string): void {
    this.defaultAppID = appID;
  }

  /**
   * Set the default App ID from environment variable
   * @throws Error if APP_INSTANCE_ID is not set
   */
  setDefaultAppIDFromEnv(): void {
    const appID = process.env.APP_INSTANCE_ID;
    if (!appID) {
      throw new Error('APP_INSTANCE_ID environment variable not set');
    }
    this.defaultAppID = appID;
  }

  /**
   * Get the currently configured default App ID
   */
  getDefaultAppID(): string {
    return this.defaultAppID;
  }

  /**
   * Get the consensus service URL
   */
  getConsensusURL(): string {
    return this.consensusURL;
  }

  /**
   * Get the request timeout in milliseconds
   */
  getRequestTimeout(): number {
    return this.requestTimeout;
  }

  /**
   * Get the pending wait timeout in milliseconds
   */
  getPendingWaitTimeout(): number {
    return this.pendingWaitTimeout;
  }

  /**
   * Sign a message using TEENet consensus
   * @param message - The message to sign
   * @param publicKey - Optional public key to use for signing
   * @returns SignResult containing the signature or pending status
   */
  async sign(message: Buffer, publicKey?: Buffer): Promise<SignResult> {
    if (!this.defaultAppID) {
      throw new Error('App ID not set. Call setDefaultAppID() first.');
    }
    if (!message || message.length === 0) {
      return this.signFailure(ErrorCode.INVALID_INPUT, 'message must not be empty');
    }

    const payload: Record<string, unknown> = {
      app_instance_id: this.defaultAppID,
      message: message.toString('base64'),
    };

    if (publicKey) {
      payload.public_key = publicKey.toString('base64');
    }
    this.logDebug('sign.submit', {
      appId: this.defaultAppID,
      pendingWaitTimeout: this.pendingWaitTimeout,
      statusPollInterval: DEFAULT_STATUS_POLL_INTERVAL,
    });

    let response: APIResponse;
    try {
      response = await this.post('/api/submit-request', payload);
    } catch (err) {
      const errMessage = err instanceof Error ? err.message : String(err);
      return this.signFailure(ErrorCode.SIGN_REQUEST_FAILED, `Failed to submit request: ${errMessage}`);
    }

    if (!response.success) {
      return this.signFailure(ErrorCode.SIGN_REQUEST_REJECTED, response.message || 'Signing failed');
    }

    const hash = response.hash || this.computeHash(message);
    const votingInfo: VotingInfo = {
      needsVoting: Boolean(response.needs_voting),
      currentVotes: response.current_votes ?? 0,
      requiredVotes: response.required_votes ?? 0,
      status: response.status || '',
      hash,
    };

    if (votingInfo.status === 'pending') {
      const waitTimeout = this.pendingWaitTimeout > 0
        ? this.pendingWaitTimeout
        : DEFAULT_PENDING_WAIT_TIMEOUT;
      this.logDebug('sign.pending', {
        hash,
        currentVotes: votingInfo.currentVotes,
        requiredVotes: votingInfo.requiredVotes,
      });
      return this.waitForSignResult(hash, waitTimeout);
    }

    const signatureHex = response.signature || '';
    if (votingInfo.status === 'signed' && signatureHex) {
      const decoded = this.decodeHexSignature(signatureHex);
      if (!decoded.success) {
        return this.signFailure(ErrorCode.SIGNATURE_DECODE_FAILED, decoded.error, votingInfo);
      }
      return {
        success: true,
        signature: decoded.signature,
        votingInfo,
      };
    }

    return this.signFailure(
      ErrorCode.UNEXPECTED_STATUS,
      `Unexpected response status: ${votingInfo.status || 'unknown'}`,
      votingInfo
    );
  }

  /**
   * Get voting status for a specific hash
   */
  async getStatus(hash: string): Promise<VoteStatus> {
    if (!hash) {
      throw new Error('hash is required');
    }

    const response = await this.getCacheDetail(`/api/cache/${hash}`);
    if (!response.found || !response.entry) {
      return {
        found: false,
        hash,
        status: 'not_found',
        currentVotes: 0,
        requiredVotes: 0,
        errorMessage: response.message,
      };
    }

    const entry = response.entry;
    const currentVotes = this.countApprovals(entry.requests);
    let signature: Buffer | undefined;
    let errorMessage = entry.error_message;
    if (entry.signature) {
      const decoded = this.decodeHexSignature(entry.signature);
      if (decoded.success) {
        signature = decoded.signature;
      } else {
        errorMessage = errorMessage || decoded.error;
      }
    }

    return {
      found: true,
      hash: entry.hash,
      status: entry.status,
      currentVotes,
      requiredVotes: entry.required_votes,
      signature,
      errorMessage,
    };
  }

  async approvalRequestInit(payload: Record<string, unknown>, approvalToken: string): Promise<ApprovalResult> {
    return this.requestApproval('/api/approvals/request/init', 'POST', approvalToken, payload);
  }

  async passkeyLoginOptions(): Promise<ApprovalResult> {
    return this.requestApproval('/api/auth/passkey/options', 'GET', '');
  }

  async passkeyLoginVerify(loginSessionId: number, credential: unknown): Promise<ApprovalResult> {
    return this.requestApproval('/api/auth/passkey/verify', 'POST', '', {
      login_session_id: loginSessionId,
      credential,
    });
  }

  async passkeyLoginWithCredential(
    getCredential: PasskeyCredentialProvider
  ): Promise<ApprovalResult> {
    const loginOptions = await this.passkeyLoginOptions();
    if (!loginOptions.success) {
      return loginOptions;
    }
    const loginSessionId = Number(loginOptions.data?.login_session_id);
    if (!Number.isFinite(loginSessionId) || loginSessionId <= 0) {
      return {
        success: false,
        statusCode: 500,
        error: 'invalid login_session_id in login options response',
      };
    }
    const options = loginOptions.data?.options;
    if (!options) {
      return {
        success: false,
        statusCode: 500,
        error: 'missing options in login options response',
      };
    }
    const credential = await getCredential(options);
    return this.passkeyLoginVerify(loginSessionId, credential);
  }

  async approvalPending(approvalToken: string): Promise<ApprovalResult> {
    return this.requestApproval('/api/approvals/pending', 'GET', approvalToken);
  }

  async approvalRequestChallenge(requestId: number, approvalToken: string): Promise<ApprovalResult> {
    return this.requestApproval(`/api/approvals/request/${requestId}/challenge`, 'GET', approvalToken);
  }

  async approvalRequestConfirm(requestId: number, payload: Record<string, unknown>, approvalToken: string): Promise<ApprovalResult> {
    return this.requestApproval(`/api/approvals/request/${requestId}/confirm`, 'POST', approvalToken, payload);
  }

  async approvalRequestConfirmWithCredential(
    requestId: number,
    getCredential: PasskeyCredentialProvider,
    approvalToken: string
  ): Promise<ApprovalResult> {
    const challenge = await this.approvalRequestChallenge(requestId, approvalToken);
    if (!challenge.success) {
      return challenge;
    }
    const options = challenge.data?.options || challenge.data;
    if (!options) {
      return {
        success: false,
        statusCode: 500,
        error: 'missing challenge options in request challenge response',
      };
    }
    const credential = await getCredential(options);
    return this.approvalRequestConfirm(requestId, { credential }, approvalToken);
  }

  async approvalActionChallenge(taskId: number, approvalToken: string): Promise<ApprovalResult> {
    return this.requestApproval(`/api/approvals/${taskId}/challenge`, 'GET', approvalToken);
  }

  async approvalAction(taskId: number, payload: Record<string, unknown>, approvalToken: string): Promise<ApprovalResult> {
    return this.requestApproval(`/api/approvals/${taskId}/action`, 'POST', approvalToken, payload);
  }

  async approvalActionWithCredential(
    taskId: number,
    action: string,
    getCredential: PasskeyCredentialProvider,
    approvalToken: string
  ): Promise<ApprovalResult> {
    const challenge = await this.approvalActionChallenge(taskId, approvalToken);
    if (!challenge.success) {
      return challenge;
    }
    const options = challenge.data?.options || challenge.data;
    if (!options) {
      return {
        success: false,
        statusCode: 500,
        error: 'missing challenge options in action challenge response',
      };
    }
    const credential = await getCredential(options);
    return this.approvalAction(taskId, {
      action,
      credential,
    }, approvalToken);
  }

  /**
   * Get the public key for the default App ID
   * @returns Public key information
   */
  async getPublicKey(): Promise<PublicKeyResponse> {
    if (!this.defaultAppID) {
      throw new Error('App ID not set. Call setDefaultAppID() first.');
    }

    const response = await this.get(`/api/publickey/${this.defaultAppID}`);

    if (!response.success) {
      throw new Error(response.error || 'Failed to get public key');
    }

    return {
      publicKey: response.public_key as string,
      protocol: response.protocol || '',
      curve: response.curve || '',
    };
  }

  /**
   * Verify a signature against a message
   * @param message - The original message
   * @param signature - The signature to verify
   * @returns true if the signature is valid
   */
  async verify(message: Buffer, signature: Buffer): Promise<boolean> {
    const keyInfo = await this.getPublicKey();
    const publicKeyBytes = Buffer.from(keyInfo.publicKey, 'hex');

    return verifySignature(
      message,
      publicKeyBytes,
      signature,
      keyInfo.protocol,
      keyInfo.curve
    );
  }

  /**
   * Verify a signature using a specific public key
   * @param message - The original message
   * @param signature - The signature to verify
   * @param publicKey - The public key bytes
   * @param protocol - The signature protocol ('ecdsa' or 'schnorr')
   * @param curve - The elliptic curve ('ed25519', 'secp256k1', or 'secp256r1')
   * @returns true if the signature is valid
   */
  verifyWithPublicKey(
    message: Buffer,
    signature: Buffer,
    publicKey: Buffer,
    protocol: string,
    curve: string
  ): boolean {
    return verifySignature(message, publicKey, signature, protocol, curve);
  }

  /**
   * Generate a new Schnorr key
   * @param curve - The elliptic curve to use
   * @returns The generated key information
   */
  async generateSchnorrKey(curve: string): Promise<GenerateKeyResult> {
    return this.generateKey(Protocol.Schnorr, curve);
  }

  /**
   * Generate a new ECDSA key
   * @param curve - The elliptic curve to use
   * @returns The generated key information
   */
  async generateECDSAKey(curve: string): Promise<GenerateKeyResult> {
    return this.generateKey(Protocol.ECDSA, curve);
  }

  /**
   * Generate a new cryptographic key
   * @param protocol - The signature protocol
   * @param curve - The elliptic curve
   */
  private async generateKey(protocol: string, curve: string): Promise<GenerateKeyResult> {
    if (!this.defaultAppID) {
      throw new Error('App ID not set. Call setDefaultAppID() first.');
    }

    const response = await this.post('/api/generate-key', {
      app_instance_id: this.defaultAppID,
      protocol,
      curve,
    });

    if (!response.success) {
      return {
        success: false,
        message: response.message || 'Key generation failed',
        publicKey: {} as PublicKeyInfo,
      };
    }

    const pk = response.public_key as APIPublicKeyInfo;
    return {
      success: true,
      message: response.message || 'Key generated successfully',
      publicKey: {
        id: pk.id,
        name: pk.name,
        keyData: pk.key_data,
        curve: pk.curve,
        protocol: pk.protocol,
        threshold: pk.threshold,
        participantCount: pk.participant_count,
        maxParticipantCount: pk.max_participant_count,
        applicationId: pk.application_id,
        createdByInstanceId: pk.created_by_instance_id,
      },
    };
  }

  /**
   * Get an API key by name
   * @param name - The name of the API key
   * @returns The API key value
   */
  async getAPIKey(name: string): Promise<APIKeyResult> {
    if (!this.defaultAppID) {
      throw new Error('App ID not set. Call setDefaultAppID() first.');
    }

    const response = await this.get(
      `/api/apikey/${name}?app_instance_id=${this.defaultAppID}`
    );

    if (!response.success) {
      return {
        success: false,
        apiKey: '',
        error: response.error || 'Failed to get API key',
      };
    }

    return {
      success: true,
      apiKey: response.api_key || '',
    };
  }

  /**
   * Sign a message using an API secret stored in TEE
   * @param name - The name of the API secret
   * @param message - The message to sign
   * @returns The HMAC-SHA256 signature
   */
  async signWithAPISecret(name: string, message: Buffer): Promise<APISignResult> {
    if (!this.defaultAppID) {
      throw new Error('App ID not set. Call setDefaultAppID() first.');
    }

    const response = await this.post(`/api/apikey/${name}/sign`, {
      app_instance_id: this.defaultAppID,
      message: message.toString('hex'),
    });

    if (!response.success) {
      return {
        success: false,
        signature: '',
        algorithm: '',
        error: response.error || 'Signing failed',
      };
    }

    return {
      success: true,
      signature: response.signature || '',
      algorithm: response.algorithm || 'HMAC-SHA256',
    };
  }

  /**
   * Close the client and release resources
   */
  close(): void {
    // no-op
  }

  /**
   * Make a GET request to the consensus service
   */
  private async get(path: string): Promise<APIResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.requestTimeout);

    try {
      const response = await fetch(`${this.consensusURL}${path}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
        signal: controller.signal,
      });

      return (await response.json()) as APIResponse;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async getCacheDetail(path: string): Promise<CacheDetailResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.requestTimeout);

    try {
      const response = await fetch(`${this.consensusURL}${path}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
        signal: controller.signal,
      });

      return (await response.json()) as CacheDetailResponse;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Make a POST request to the consensus service
   */
  private async post(
    path: string,
    body: Record<string, unknown>
  ): Promise<APIResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.requestTimeout);

    try {
      const response = await fetch(`${this.consensusURL}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      return (await response.json()) as APIResponse;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async requestApproval(
    path: string,
    method: 'GET' | 'POST',
    approvalToken: string,
    body?: Record<string, unknown>
  ): Promise<ApprovalResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.requestTimeout);

    try {
      const response = await fetch(`${this.consensusURL}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(approvalToken?.trim() ? { Authorization: `Bearer ${approvalToken.trim()}` } : {}),
        },
        body: method === 'POST' ? JSON.stringify(body || {}) : undefined,
        signal: controller.signal,
      });

      const data = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      const result: ApprovalResult = {
        success: response.ok,
        statusCode: response.status,
        data,
      };
      if (!response.ok) {
        const msg = typeof data.error === 'string'
          ? data.error
          : typeof data.message === 'string'
            ? data.message
            : `Approval request failed with status ${response.status}`;
        result.error = msg;
      }
      return result;
    } finally {
      clearTimeout(timeout);
    }
  }

  private computeHash(message: Buffer): string {
    return `0x${Buffer.from(sha256(message)).toString('hex')}`;
  }

  private countApprovals(requests?: Record<string, CacheRequest>): number {
    if (!requests) {
      return 0;
    }
    let count = 0;
    for (const req of Object.values(requests)) {
      if (req && req.approved) {
        count++;
      }
    }
    return count;
  }

  private async sleep(ms: number): Promise<void> {
    await new Promise<void>((resolve) => {
      setTimeout(resolve, ms);
    });
  }

  private async waitForSignResult(hash: string, timeoutMs: number): Promise<SignResult> {
    if (!hash) {
      return this.signFailure(ErrorCode.MISSING_HASH, 'missing hash in pending signing response');
    }

    const deadline = Date.now() + timeoutMs;
    let latestVotes = 0;
    let latestRequiredVotes = 0;
    const startedAt = Date.now();
    let attempt = 0;

    while (Date.now() <= deadline) {
      attempt += 1;
      let status: VoteStatus;
      try {
        status = await this.getStatus(hash);
      } catch (err) {
        const errMessage = err instanceof Error ? err.message : String(err);
        return this.signFailure(ErrorCode.STATUS_QUERY_FAILED, `failed to query voting status: ${errMessage}`, {
          needsVoting: true,
          currentVotes: latestVotes,
          requiredVotes: latestRequiredVotes,
          status: 'pending',
          hash,
        });
      }

      if (status.found) {
        latestVotes = status.currentVotes;
        latestRequiredVotes = status.requiredVotes;
        this.logDebug('sign.poll', {
          hash,
          attempt,
          elapsedMs: Date.now() - startedAt,
          status: status.status,
          votes: `${status.currentVotes}/${status.requiredVotes}`,
        });

        if (status.status === 'signed' && status.signature && status.signature.length > 0) {
          return {
            success: true,
            signature: status.signature,
            votingInfo: {
              needsVoting: true,
              currentVotes: status.currentVotes,
              requiredVotes: status.requiredVotes,
              status: 'signed',
              hash,
            },
          };
        }

        if (status.status === 'failed') {
          const error = status.errorMessage || 'Signing failed';
          return this.signFailure(ErrorCode.SIGN_FAILED, error, {
            needsVoting: true,
            currentVotes: status.currentVotes,
            requiredVotes: status.requiredVotes,
            status: 'failed',
            hash,
          });
        }

        if (status.status === 'signed' && (!status.signature || status.signature.length === 0)) {
          const error = status.errorMessage || 'Failed to decode signature from signed status';
          return this.signFailure(ErrorCode.SIGNATURE_DECODE_FAILED, error, {
            needsVoting: true,
            currentVotes: status.currentVotes,
            requiredVotes: status.requiredVotes,
            status: 'signed',
            hash,
          });
        }
      }

      const sleepMs = this.nextPollInterval(attempt);
      await this.sleep(Math.min(sleepMs, Math.max(0, deadline - Date.now())));
    }

    return this.signFailure(
      ErrorCode.THRESHOLD_TIMEOUT,
      `Threshold not met before timeout for hash ${hash}: votes ${latestVotes}/${latestRequiredVotes}`,
      {
        needsVoting: true,
        currentVotes: latestVotes,
        requiredVotes: latestRequiredVotes,
        status: 'pending',
        hash,
      }
    );
  }

  private nextPollInterval(attempt: number): number {
    const normalizedBase = Math.max(DEFAULT_STATUS_POLL_INTERVAL, 10);
    const shift = Math.min(Math.max(attempt - 1, 0), 4);
    const exp = Math.min(normalizedBase * (2 ** shift), MAX_STATUS_POLL_INTERVAL);
    const jitter = 0.8 + Math.random() * 0.4; // +/-20%
    return Math.max(10, Math.floor(exp * jitter));
  }

  private decodeHexSignature(input: string): { success: true; signature: Buffer } | { success: false; error: string } {
    const normalized = input.replace(/^0x/, '');
    if (!normalized || !/^[0-9a-fA-F]+$/.test(normalized) || normalized.length % 2 !== 0) {
      return { success: false, error: `invalid signature hex: ${input}` };
    }
    return { success: true, signature: Buffer.from(normalized, 'hex') };
  }

  private signFailure(errorCode: ErrorCodeType, error: string, votingInfo?: VotingInfo): SignResult {
    return {
      success: false,
      signature: Buffer.alloc(0),
      error,
      errorCode,
      votingInfo,
    };
  }

  private logDebug(event: string, fields: Record<string, unknown>): void {
    if (!this.debug) return;
    const serialized = Object.entries(fields).map(([k, v]) => `${k}=${String(v)}`).join(' ');
    console.debug(`[teenet-sdk] ${event} ${serialized}`);
  }
}
