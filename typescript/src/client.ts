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

import {
  ClientOptions,
  SignResult,
  GenerateKeyResult,
  APIKeyResult,
  APISignResult,
  PublicKeyResponse,
  Protocol,
  PublicKeyInfo,
} from './types';
import { verifySignature } from './crypto';

const DEFAULT_REQUEST_TIMEOUT = 30000;
const DEFAULT_CALLBACK_TIMEOUT = 60000;

interface APIResponse {
  success: boolean;
  message?: string;
  error?: string;
  signature?: string;
  signature_hex?: string;
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
  private callbackTimeout: number;

  /**
   * Create a new TEENet SDK client
   * @param consensusURL - Base URL of the consensus service
   * @param options - Optional configuration
   */
  constructor(consensusURL: string, options?: ClientOptions) {
    this.consensusURL = consensusURL.replace(/\/$/, ''); // Remove trailing slash
    this.requestTimeout = options?.requestTimeout ?? DEFAULT_REQUEST_TIMEOUT;
    this.callbackTimeout = options?.callbackTimeout ?? DEFAULT_CALLBACK_TIMEOUT;
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
   * Get the callback timeout in milliseconds
   */
  getCallbackTimeout(): number {
    return this.callbackTimeout;
  }

  /**
   * Sign a message using TEENet consensus
   * @param message - The message to sign
   * @param publicKey - Optional public key to use for signing
   * @returns SignResult containing the signature
   */
  async sign(message: Buffer, publicKey?: Buffer): Promise<SignResult> {
    if (!this.defaultAppID) {
      throw new Error('App ID not set. Call setDefaultAppID() first.');
    }

    const payload: Record<string, unknown> = {
      app_instance_id: this.defaultAppID,
      message: message.toString('base64'),
    };

    if (publicKey) {
      payload.public_key = publicKey.toString('base64');
    }

    const response = await this.post('/api/submit-request', payload);

    if (!response.success) {
      return {
        success: false,
        signature: Buffer.alloc(0),
        error: response.message || 'Signing failed',
      };
    }

    const signatureHex = response.signature || '';
    const signature = Buffer.from(signatureHex, 'hex');

    return {
      success: true,
      signature,
    };
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
      signature: response.signature || response.signature_hex || '',
      algorithm: response.algorithm || 'HMAC-SHA256',
    };
  }

  /**
   * Close the client and release resources
   */
  close(): void {
    // No persistent connections to close in this implementation
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
}
