// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

import {
  ClientOptions,
  SignResult,
  VotingInfo,
  VoteStatus,
  ApprovalResult,
  ApprovalPendingFilter,
  PasskeyCredentialProvider,
  GenerateKeyResult,
  APIKeyResult,
  APISignResult,
  BoundPublicKeyInfo,
  Protocol,
  PublicKeyInfo,
  ErrorCode,
  ErrorCodeType,
  PasskeyInviteRequest,
  PasskeyInviteResult,
  PasskeyUsersResult,
  AuditRecordsResult,
  PolicyRequest,
  PolicyResult,
  AdminResult,
} from './types';
import { verifySignature } from './crypto';
import { sha256 } from '@noble/hashes/sha256';

const DEFAULT_REQUEST_TIMEOUT = 30000;
const DEFAULT_PENDING_WAIT_TIMEOUT = 10 * 1000;
const DEFAULT_STATUS_POLL_INTERVAL = 200;
const MAX_STATUS_POLL_INTERVAL = 5000;

const MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB

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
  public_keys?: APIPublicKeyInfo[];
  protocol?: string;
  curve?: string;
  api_key?: string;
  algorithm?: string;
  tx_id?: string;
  request_id?: number;
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
 * client.setDefaultAppInstanceID('your-app-id');
 *
 * // Sign a message
 * const result = await client.sign(Buffer.from('message'), 'my-key');
 * if (result.success) {
 *   console.log('Signature:', result.signature.toString('hex'));
 * }
 *
 * // Verify a signature
 * const valid = await client.verify(message, result.signature, 'my-key');
 * ```
 */
export class Client {
  private consensusURL: string;
  private defaultAppInstanceID: string = '';
  private requestTimeout: number;
  private pendingWaitTimeout: number;
  private debug: boolean;
  private keyCacheTTL: number;
  private keyCache: Map<string, { keys: BoundPublicKeyInfo[]; expiresAt: number }> = new Map();

  /**
   * Create a new TEENet SDK client.
   *
   * The client is created in an uninitialized state. Call {@link init} to
   * load `APP_INSTANCE_ID` from `process.env` (containers deployed by the
   * App Lifecycle Manager have it injected automatically), or call
   * {@link setDefaultAppInstanceID} to set it explicitly.
   *
   * @param consensusURL - Base URL of the consensus service
   * @param options - Optional configuration
   */
  constructor(consensusURL: string, options?: ClientOptions) {
    this.consensusURL = consensusURL.replace(/\/$/, ''); // Remove trailing slash
    this.requestTimeout = options?.requestTimeout ?? DEFAULT_REQUEST_TIMEOUT;
    this.pendingWaitTimeout = Math.max(options?.pendingWaitTimeout ?? DEFAULT_PENDING_WAIT_TIMEOUT, 0);
    this.debug = Boolean(options?.debug);
    this.keyCacheTTL = options?.keyCacheTTL ?? 60000; // Default 60s, -1 to disable
  }

  /**
   * Initialize client from environment variables.
   * Reads `APP_INSTANCE_ID` from `process.env` and sets it as the default.
   * Useful for containers deployed by the App Lifecycle Manager, which
   * automatically injects `APP_INSTANCE_ID` and `CONSENSUS_URL`.
   */
  init(): void {
    const appID = process.env.APP_INSTANCE_ID;
    if (appID) {
      this.defaultAppInstanceID = appID;
    } else {
      console.warn('APP_INSTANCE_ID environment variable not set');
    }
  }

  /**
   * Set the default application ID
   * @param appID - Your TEENet application ID
   */
  setDefaultAppInstanceID(appID: string): void {
    this.defaultAppInstanceID = appID;
  }

  /**
   * Set the default App ID from environment variable
   * @throws Error if APP_INSTANCE_ID is not set
   */
  setDefaultAppInstanceIDFromEnv(): void {
    const appID = process.env.APP_INSTANCE_ID;
    if (!appID) {
      throw new Error('APP_INSTANCE_ID environment variable not set');
    }
    this.defaultAppInstanceID = appID;
  }

  /**
   * Get the currently configured default App ID
   */
  getDefaultAppInstanceID(): string {
    return this.defaultAppInstanceID;
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
   * @param publicKeyName - Bound public key name to use for signing
   * @returns SignResult containing the signature or pending status
   */
  async sign(message: Buffer, publicKeyName: string, passkeyToken?: string): Promise<SignResult> {
    if (!this.defaultAppInstanceID) {
      throw new Error('App ID not set. Call setDefaultAppInstanceID() first.');
    }
    if (!message || message.length === 0) {
      return this.signFailure(ErrorCode.INVALID_INPUT, 'message must not be empty');
    }

    const payload: Record<string, unknown> = {
      app_instance_id: this.defaultAppInstanceID,
      message: message.toString('base64'),
    };
    if (passkeyToken) {
      payload.passkey_token = passkeyToken;
    }

    if (!publicKeyName || !publicKeyName.trim()) {
      return this.signFailure(ErrorCode.INVALID_INPUT, 'public key name is required');
    }
    let keyInfo: BoundPublicKeyInfo;
    try {
      keyInfo = await this.getBoundPublicKeyByName(publicKeyName);
    } catch (err) {
      const errMessage = err instanceof Error ? err.message : String(err);
      return this.signFailure(ErrorCode.INVALID_INPUT, errMessage);
    }
    const keyHex = keyInfo.keyData.startsWith('0x') ? keyInfo.keyData.slice(2) : keyInfo.keyData;
    payload.public_key = Buffer.from(keyHex, 'hex').toString('base64');
    this.logDebug('sign.submit', {
      appId: this.defaultAppInstanceID,
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
      txID: response.tx_id,
      requestID: response.request_id,
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

    if (votingInfo.status === 'pending_approval') {
      this.logDebug('sign.pending_approval', {
        hash,
        txID: votingInfo.txID,
        requestID: votingInfo.requestID,
      });
      return this.signFailure(ErrorCode.APPROVAL_PENDING, 'approval pending: request requires passkey approval', votingInfo);
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

    const response = await this.getCacheDetail(`/api/cache/${encodeURIComponent(hash)}`);
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

  async approvalPending(approvalToken: string, filter?: ApprovalPendingFilter): Promise<ApprovalResult> {
    const query = new URLSearchParams();
    const applicationId = Number(filter?.applicationId ?? 0);
    const publicKeyName = String(filter?.publicKeyName ?? '').trim();

    if (applicationId > 0) {
      query.set('application_id', String(applicationId));
    }
    if (publicKeyName) {
      if (applicationId <= 0) {
        return {
          success: false,
          statusCode: 0,
          error: 'application_id is required when public_key_name is provided',
        };
      }
      query.set('public_key_name', publicKeyName);
    }

    const queryString = query.toString();
    const path = queryString ? `/api/approvals/pending?${queryString}` : '/api/approvals/pending';
    return this.requestApproval(path, 'GET', approvalToken);
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
   * Get all bound public keys for the default App ID
   */
  async getPublicKeys(): Promise<BoundPublicKeyInfo[]> {
    if (!this.defaultAppInstanceID) {
      throw new Error('App ID not set. Call setDefaultAppInstanceID() first.');
    }

    // Check cache (evict expired entry if stale)
    if (this.keyCacheTTL > 0) {
      const cached = this.keyCache.get(this.defaultAppInstanceID);
      if (cached) {
        if (Date.now() < cached.expiresAt) {
          return cached.keys;
        }
        this.keyCache.delete(this.defaultAppInstanceID);
      }
    }

    const response = await this.get(`/api/publickeys/${encodeURIComponent(this.defaultAppInstanceID)}`);
    if (!response.success) {
      throw new Error(response.error || 'Failed to get public keys');
    }

    const keys = (response.public_keys || []) as APIPublicKeyInfo[];
    const result = keys.map((key) => ({
      id: key.id,
      name: key.name,
      keyData: key.key_data,
      protocol: key.protocol,
      curve: key.curve,
      threshold: key.threshold,
      participantCount: key.participant_count,
      maxParticipantCount: key.max_participant_count,
      applicationId: key.application_id,
      createdByInstanceId: key.created_by_instance_id,
    }));

    // Store in cache
    if (this.keyCacheTTL > 0) {
      this.keyCache.set(this.defaultAppInstanceID, {
        keys: result,
        expiresAt: Date.now() + this.keyCacheTTL,
      });
    }

    return result;
  }

  private async getBoundPublicKeyByName(publicKeyName: string): Promise<BoundPublicKeyInfo> {
    const keyName = publicKeyName.trim();
    if (!keyName) {
      throw new Error('public key name is required');
    }
    const keys = await this.getPublicKeys();
    const matched = keys.find((key) => key.name === keyName);
    if (!matched) {
      throw new Error(`public key name '${keyName}' is not bound to this application`);
    }
    return matched;
  }

  /**
   * Verify a signature against a message
   * @param message - The message to verify. For most protocols this is the raw bytes
   *   and hashing is done internally. Exception: for SECP256K1+ECDSA, the caller must
   *   pass the pre-hashed digest (e.g. a 32-byte Keccak-256 or SHA-256 hash).
   * @param signature - The signature to verify
   * @param publicKeyName - Bound public key name used to verify
   * @returns true if the signature is valid
   */
  async verify(message: Buffer, signature: Buffer, publicKeyName: string): Promise<boolean> {
    const keyInfo = await this.getBoundPublicKeyByName(publicKeyName);
    const keyHex = keyInfo.keyData.startsWith('0x') ? keyInfo.keyData.slice(2) : keyInfo.keyData;
    const publicKeyBytes = Buffer.from(keyHex, 'hex');

    return verifySignature(
      message,
      publicKeyBytes,
      signature,
      keyInfo.protocol,
      keyInfo.curve
    );
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
    if (!this.defaultAppInstanceID) {
      throw new Error('App ID not set. Call setDefaultAppInstanceID() first.');
    }

    const response = await this.post('/api/generate-key', {
      app_instance_id: this.defaultAppInstanceID,
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
    if (!this.defaultAppInstanceID) {
      throw new Error('App ID not set. Call setDefaultAppInstanceID() first.');
    }

    const response = await this.get(
      `/api/apikey/${encodeURIComponent(name)}?${new URLSearchParams({ app_instance_id: this.defaultAppInstanceID })}`
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
    if (!this.defaultAppInstanceID) {
      throw new Error('App ID not set. Call setDefaultAppInstanceID() first.');
    }

    const response = await this.post(`/api/apikey/${encodeURIComponent(name)}/sign`, {
      app_instance_id: this.defaultAppInstanceID,
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

  // ─── Admin management ─────────────────────────────────────────────────────

  /**
   * Invite a new passkey user to the application.
   */
  async invitePasskeyUser(req: PasskeyInviteRequest): Promise<PasskeyInviteResult> {
    if (!this.defaultAppInstanceID) {
      return { success: false, error: 'App ID not set. Call setDefaultAppInstanceID() first.' };
    }
    const body: Record<string, unknown> = {
      app_instance_id: this.defaultAppInstanceID,
      display_name: req.displayName,
    };
    if (req.applicationId && req.applicationId > 0) body.application_id = req.applicationId;
    if (req.expiresInSeconds && req.expiresInSeconds > 0) body.expires_in_seconds = req.expiresInSeconds;

    const resp = await this.requestAdmin('/api/admin/passkey/invite', 'POST', body);
    const d = resp.data ?? {};
    const ok = resp.statusCode >= 200 && resp.statusCode < 300;
    return {
      success: ok,
      error: ok ? undefined : this.adminError(d, resp.statusCode),
      inviteToken: typeof d.invite_token === 'string' ? d.invite_token : undefined,
      registerUrl: typeof d.register_url === 'string' ? d.register_url : undefined,
      expiresAt: typeof d.expires_at === 'string' ? d.expires_at : undefined,
    };
  }

  /**
   * List registered passkey users for this application.
   * @param page - Page number (0 = server default)
   * @param limit - Page size (0 = server default)
   */
  async listPasskeyUsers(page = 0, limit = 0): Promise<PasskeyUsersResult> {
    if (!this.defaultAppInstanceID) {
      return { success: false, error: 'App ID not set.', users: [], total: 0, page: 0, limit: 0 };
    }
    const q = new URLSearchParams({ app_instance_id: this.defaultAppInstanceID });
    if (page > 0) q.set('page', String(page));
    if (limit > 0) q.set('limit', String(limit));
    const resp = await this.requestAdmin(`/api/admin/passkey/users?${q}`, 'GET');
    const d = resp.data ?? {};
    const ok = resp.statusCode >= 200 && resp.statusCode < 300;
    return {
      success: ok,
      error: ok ? undefined : this.adminError(d, resp.statusCode),
      users: Array.isArray(d.users) ? d.users.map(this.mapPasskeyUser) : [],
      total: typeof d.total === 'number' ? d.total : 0,
      page: typeof d.page === 'number' ? d.page : 0,
      limit: typeof d.limit === 'number' ? d.limit : 0,
    };
  }

  /**
   * Delete a passkey user by their ID.
   */
  async deletePasskeyUser(userId: number): Promise<AdminResult> {
    if (!this.defaultAppInstanceID) {
      return { success: false, error: 'App ID not set.' };
    }
    const q = new URLSearchParams({ app_instance_id: this.defaultAppInstanceID });
    const resp = await this.requestAdmin(`/api/admin/passkey/users/${userId}?${q}`, 'DELETE');
    const ok = resp.statusCode >= 200 && resp.statusCode < 300;
    return {
      success: ok,
      error: ok ? undefined : this.adminError(resp.data ?? {}, resp.statusCode),
    };
  }

  /**
   * List audit records for this application.
   * @param page - Page number (0 = server default)
   * @param limit - Page size (0 = server default)
   */
  async listAuditRecords(page = 0, limit = 0): Promise<AuditRecordsResult> {
    if (!this.defaultAppInstanceID) {
      return { success: false, error: 'App ID not set.', records: [], total: 0, page: 0, limit: 0 };
    }
    const q = new URLSearchParams({ app_instance_id: this.defaultAppInstanceID });
    if (page > 0) q.set('page', String(page));
    if (limit > 0) q.set('limit', String(limit));
    const resp = await this.requestAdmin(`/api/admin/audit-records?${q}`, 'GET');
    const d = resp.data ?? {};
    const ok = resp.statusCode >= 200 && resp.statusCode < 300;
    return {
      success: ok,
      error: ok ? undefined : this.adminError(d, resp.statusCode),
      records: Array.isArray(d.records) ? d.records.map(this.mapAuditRecord) : [],
      total: typeof d.total === 'number' ? d.total : 0,
      page: typeof d.page === 'number' ? d.page : 0,
      limit: typeof d.limit === 'number' ? d.limit : 0,
    };
  }

  /**
   * Create or replace the permission policy for a named public key.
   */
  async upsertPermissionPolicy(req: PolicyRequest): Promise<AdminResult> {
    if (!this.defaultAppInstanceID) {
      return { success: false, error: 'App ID not set.' };
    }
    const body: Record<string, unknown> = {
      app_instance_id: this.defaultAppInstanceID,
      public_key_name: req.publicKeyName,
      enabled: req.enabled,
      levels: req.levels.map((l) => ({
        level_index: l.levelIndex,
        threshold: l.threshold,
        member_ids: l.memberIds,
      })),
    };
    if (req.timeoutSeconds && req.timeoutSeconds > 0) body.timeout_seconds = req.timeoutSeconds;

    const resp = await this.requestAdmin('/api/admin/policy', 'PUT', body);
    const ok = resp.statusCode >= 200 && resp.statusCode < 300;
    return {
      success: ok,
      error: ok ? undefined : this.adminError(resp.data ?? {}, resp.statusCode),
    };
  }

  /**
   * Retrieve the permission policy for a named public key.
   */
  async getPermissionPolicy(publicKeyName: string): Promise<PolicyResult> {
    if (!this.defaultAppInstanceID) {
      return { success: false, error: 'App ID not set.' };
    }
    const q = new URLSearchParams({
      app_instance_id: this.defaultAppInstanceID,
      public_key_name: publicKeyName,
    });
    const resp = await this.requestAdmin(`/api/admin/policy?${q}`, 'GET');
    const d = resp.data ?? {};
    const ok = resp.statusCode >= 200 && resp.statusCode < 300;
    if (!ok) {
      return { success: false, error: this.adminError(d, resp.statusCode) };
    }
    const policyData = (d.policy as Record<string, unknown>) ?? d;
    return { success: true, policy: this.mapPolicy(policyData) };
  }

  /**
   * List all approval requests initiated by the authenticated user.
   */
  async getMyRequests(approvalToken: string): Promise<ApprovalResult> {
    return this.requestApproval('/api/requests/mine', 'GET', approvalToken);
  }

  /**
   * Retrieve a completed signature by its transaction ID.
   */
  async getSignatureByTx(txId: string, approvalToken: string): Promise<ApprovalResult> {
    return this.requestApproval(`/api/signature/by-tx/${encodeURIComponent(txId)}`, 'GET', approvalToken);
  }

  /**
   * Delete the permission policy for a named public key.
   */
  async deletePermissionPolicy(publicKeyName: string): Promise<AdminResult> {
    return this.adminDelete('/api/admin/policy', { public_key_name: publicKeyName });
  }

  /**
   * Cancel a pending approval request.
   * @param id - Request session ID or task ID
   * @param idType - "session" (default) or "task"
   */
  async cancelRequest(id: number, idType?: string, approvalToken?: string): Promise<ApprovalResult> {
    const type = idType || 'session';
    return this.requestApproval(
      `/api/approvals/requests/${encodeURIComponent(String(id))}/cancel?type=${encodeURIComponent(type)}`,
      'POST',
      approvalToken || ''
    );
  }

  /**
   * Get passkey registration options for an invited user.
   */
  async passkeyRegistrationOptions(inviteToken: string): Promise<ApprovalResult> {
    return this.requestApproval(
      `/api/approvals/registration/options?token=${encodeURIComponent(inviteToken)}`,
      'GET',
      ''
    );
  }

  /**
   * Complete passkey registration with the WebAuthn credential.
   */
  async passkeyRegistrationVerify(inviteToken: string, credential: unknown): Promise<ApprovalResult> {
    return this.requestApproval(
      '/api/approvals/registration/verify',
      'POST',
      '',
      { invite_token: inviteToken, credential }
    );
  }

  /**
   * Verify passkey login and confirm the passkey belongs to expectedPasskeyUserID.
   */
  async passkeyLoginVerifyAs(
    loginSessionID: number,
    credential: unknown,
    expectedPasskeyUserID: number
  ): Promise<ApprovalResult> {
    return this.requestApproval(
      '/api/approvals/login/verify-as',
      'POST',
      '',
      {
        login_session_id: loginSessionID,
        credential,
        expected_passkey_user_id: expectedPasskeyUserID,
      }
    );
  }

  /**
   * Delete a public key by name.
   */
  async deletePublicKey(keyName: string): Promise<AdminResult> {
    return this.adminDelete(`/api/admin/publickeys/${encodeURIComponent(keyName)}`);
  }

  /**
   * Create a new API key via admin bridge.
   */
  async createAPIKey(req: import('./types').CreateAPIKeyRequest): Promise<import('./types').CreateAPIKeyResult> {
    if (!this.defaultAppInstanceID) {
      return { success: false, error: 'App ID not set.' };
    }
    const resp = await this.requestAdmin('/api/admin/apikeys', 'POST', {
      app_instance_id: this.defaultAppInstanceID,
      name: req.name,
      description: req.description,
      api_key: req.apiKey,
      api_secret: req.apiSecret,
    });
    const ok = resp.statusCode >= 200 && resp.statusCode < 300;
    const d = resp.data ?? {};
    return {
      success: ok,
      error: ok ? undefined : this.adminError(d, resp.statusCode),
      id: typeof d.id === 'number' ? d.id : undefined,
      name: typeof d.name === 'string' ? d.name : undefined,
      hasApiKey: typeof d.has_api_key === 'boolean' ? d.has_api_key : undefined,
      hasApiSecret: typeof d.has_api_secret === 'boolean' ? d.has_api_secret : undefined,
    };
  }

  /**
   * Delete an API key by name.
   */
  async deleteAPIKey(keyName: string): Promise<AdminResult> {
    return this.adminDelete(`/api/admin/apikeys/${encodeURIComponent(keyName)}`);
  }

  /**
   * Clear any locally cached public keys (no-op in TypeScript SDK,
   * present for API parity with Go SDK).
   */
  invalidateKeyCache(): void {
    this.keyCache.clear();
  }

  private async adminDelete(path: string, extraParams?: Record<string, string>): Promise<AdminResult> {
    if (!this.defaultAppInstanceID) {
      return { success: false, error: 'App ID not set.' };
    }
    const q = new URLSearchParams({ app_instance_id: this.defaultAppInstanceID, ...extraParams });
    const resp = await this.requestAdmin(`${path}?${q}`, 'DELETE');
    const ok = resp.statusCode >= 200 && resp.statusCode < 300;
    return {
      success: ok,
      error: ok ? undefined : this.adminError(resp.data ?? {}, resp.statusCode),
    };
  }

  // ─── Admin helpers ─────────────────────────────────────────────────────────

  private async requestAdmin(
    path: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    body?: Record<string, unknown>
  ): Promise<{ statusCode: number; data: Record<string, unknown> }> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.requestTimeout);
    try {
      const response = await fetch(`${this.consensusURL}${path}`, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: (method === 'POST' || method === 'PUT') ? JSON.stringify(body ?? {}) : undefined,
        signal: controller.signal,
      });
      this.checkResponseSize(response);
      const data = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      return { statusCode: response.status, data };
    } finally {
      clearTimeout(timeout);
    }
  }

  private adminError(data: Record<string, unknown>, statusCode: number): string {
    if (typeof data.message === 'string' && data.message) return data.message;
    if (typeof data.error === 'string' && data.error) return data.error;
    return `Admin request failed with status ${statusCode}`;
  }

  private mapPasskeyUser(raw: unknown): import('./types').PasskeyUser {
    const u = raw as Record<string, unknown>;
    return {
      id: typeof u.id === 'number' ? u.id : 0,
      displayName: typeof u.display_name === 'string' ? u.display_name : '',
      userHandle: typeof u.user_handle === 'string' ? u.user_handle : undefined,
      applicationId: typeof u.application_id === 'number' ? u.application_id : undefined,
      createdAt: typeof u.created_at === 'string' ? u.created_at : undefined,
    };
  }

  private mapAuditRecord(raw: unknown): import('./types').AuditRecord {
    const r = raw as Record<string, unknown>;
    return {
      id: typeof r.id === 'number' ? r.id : 0,
      taskId: typeof r.task_id === 'number' ? r.task_id : undefined,
      requestSessionId: typeof r.request_session_id === 'number' ? r.request_session_id : undefined,
      eventType: typeof r.event_type === 'string' ? r.event_type : undefined,
      action: typeof r.action === 'string' ? r.action : undefined,
      status: typeof r.status === 'string' ? r.status : undefined,
      actorPasskeyUserId: typeof r.actor_passkey_user_id === 'number' ? r.actor_passkey_user_id : undefined,
      actorDisplayName: typeof r.actor_display_name === 'string' ? r.actor_display_name : undefined,
      txId: typeof r.tx_id === 'string' ? r.tx_id : undefined,
      hash: typeof r.hash === 'string' ? r.hash : undefined,
      signature: typeof r.signature === 'string' ? r.signature : undefined,
      appInstanceId: typeof r.app_instance_id === 'string' ? r.app_instance_id : undefined,
      details: typeof r.details === 'string' ? r.details : undefined,
      errorMessage: typeof r.error_message === 'string' ? r.error_message : undefined,
      createdAt: typeof r.created_at === 'string' ? r.created_at : undefined,
    };
  }

  private mapPolicy(d: Record<string, unknown>): import('./types').Policy | undefined {
    if (!d || typeof d.id !== 'number') return undefined;
    const levels = Array.isArray(d.levels)
      ? (d.levels as Array<Record<string, unknown>>).map((l) => ({
          levelIndex: typeof l.level_index === 'number' ? l.level_index : 0,
          threshold: typeof l.threshold === 'number' ? l.threshold : 0,
          memberIds: Array.isArray(l.member_ids) ? (l.member_ids as number[]) : [],
        }))
      : undefined;
    return {
      id: d.id as number,
      applicationId: typeof d.application_id === 'number' ? d.application_id : 0,
      publicKeyId: typeof d.public_key_id === 'number' ? d.public_key_id : 0,
      publicKeyName: typeof d.public_key_name === 'string' ? d.public_key_name : undefined,
      enabled: Boolean(d.enabled),
      timeoutSeconds: typeof d.timeout_seconds === 'number' ? d.timeout_seconds : 0,
      levels,
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

      this.checkResponseSize(response);
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

      this.checkResponseSize(response);
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

      this.checkResponseSize(response);
      return (await response.json()) as APIResponse;
    } finally {
      clearTimeout(timeout);
    }
  }

  private checkResponseSize(response: Response): void {
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_SIZE) {
      throw new Error(`Response too large: ${contentLength} bytes (max ${MAX_RESPONSE_SIZE})`);
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
