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

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as fs from 'fs';
import * as path from 'path';
import { NodeConfig, SignRequest, SignResponse } from './types';

interface UserTaskClient {
  Sign(request: any, callback: (error: grpc.ServiceError | null, response?: any) => void): grpc.ClientUnaryCall;
}

export class TaskClient {
  private config: NodeConfig;
  private client: UserTaskClient | null = null;
  private conn: grpc.Client | null = null;

  constructor(nodeConfig: NodeConfig) {
    this.config = nodeConfig;
  }

  async connect(timeout?: number): Promise<void> {
    if (this.conn) {
      this.conn.close();
    }

    try {
      const tlsConfig = this.createTLSConfig();
      
      const protoPath = path.resolve(__dirname, '../proto/key_management/user_task.proto');
      const packageDefinition = protoLoader.loadSync(protoPath, {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
      });

      const userTaskProto = grpc.loadPackageDefinition(packageDefinition) as any;
      const UserTaskClient = userTaskProto.UserTask;

      const options: grpc.ChannelOptions = {
        'grpc.keepalive_time_ms': 30000,
        'grpc.keepalive_timeout_ms': 5000,
        'grpc.keepalive_permit_without_calls': 1,
        'grpc.http2.max_pings_without_data': 0,
        'grpc.http2.min_time_between_pings_ms': 10000,
        'grpc.http2.min_ping_interval_without_data_ms': 300000,
      };

      this.client = new UserTaskClient(
        this.config.rpcAddress,
        tlsConfig,
        options
      );

      this.conn = this.client as any;
    } catch (error) {
      throw new Error(`failed to connect to TEE server: ${error}`);
    }
  }

  async close(): Promise<void> {
    if (this.conn) {
      this.conn.close();
      this.conn = null;
      this.client = null;
    }
  }

  async sign(message: Uint8Array, publicKey: Uint8Array, protocol: number, curve: number, timeout: number): Promise<Uint8Array> {
    if (!message || message.length === 0) {
      throw new Error('message cannot be empty');
    }
    if (!publicKey || publicKey.length === 0) {
      throw new Error('public key cannot be empty');
    }
    if (!this.client) {
      throw new Error('not connected to server');
    }

    return new Promise((resolve, reject) => {
      const deadline = Date.now() + timeout;

      const request = {
        from: this.config.nodeId,
        msg: Array.from(message),
        public_key_info: Array.from(publicKey),
        protocol: protocol,
        curve: curve
      };

      this.client!.Sign(request, (error: grpc.ServiceError | null, response?: any) => {
        if (error) {
          reject(new Error(`gRPC call failed [${error.code}]: ${error.message}`));
          return;
        }

        if (!response) {
          reject(new Error('no response received'));
          return;
        }

        if (!response.success) {
          reject(new Error(`signing failed: ${response.error || 'unknown error'}`));
          return;
        }

        const signature = response.signature;
        if (signature && signature.data) {
          resolve(new Uint8Array(signature.data));
        } else if (signature) {
          resolve(new Uint8Array(signature));
        } else {
          resolve(new Uint8Array());
        }
      });
    });
  }


  private createTLSConfig(): grpc.ChannelCredentials {
    try {
      // Ensure certificates and keys are in Buffer format
      const clientCert = Buffer.isBuffer(this.config.cert) ? this.config.cert : Buffer.from(this.config.cert);
      const clientKey = Buffer.isBuffer(this.config.key) ? this.config.key : Buffer.from(this.config.key);
      const serverCert = Buffer.isBuffer(this.config.targetCert) ? this.config.targetCert : Buffer.from(this.config.targetCert);

      // Use standard TLS configuration with proper certificate validation
      return grpc.credentials.createSsl(serverCert, clientKey, clientCert);
    } catch (error) {
      throw new Error(`failed to create TLS config: ${error}`);
    }
  }

}