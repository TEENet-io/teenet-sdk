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
import * as path from 'path';
import * as tls from 'tls';
import { DeploymentTarget } from './types';

export interface GetPublicKeyByAppIDRequest {
  app_id: string;
}

export interface GetPublicKeyByAppIDResponse {
  publickey: string;
  protocol: string;
  curve: string;
}

export interface GetDeploymentAddressesRequest {
  app_id: string;  // Single App ID to get all target deployment addresses for
}

export interface DeploymentInfo {
  app_id: string;
  project_name: string;
  deployment_host: string;
  container_ip: string;
  service_port: number;
  deployment_client_address: string;
  deployed_at: number;
  deployment_type: string;
}

export interface GetDeploymentAddressesResponse {
  deployments: { [appId: string]: DeploymentInfo };
  not_found: string[];
  voting_sign_path?: string;  // Shared VotingSign API path for all instances
  required_votes?: number;    // Shared required votes for all instances
  enable_voting_sign?: boolean; // Whether voting sign is enabled for this project
}

interface AppIDServiceClient {
  GetPublicKeyByAppID(
    request: GetPublicKeyByAppIDRequest,
    callback: (error: grpc.ServiceError | null, response?: GetPublicKeyByAppIDResponse) => void
  ): grpc.ClientUnaryCall;
  
  GetDeploymentAddresses(
    request: GetDeploymentAddressesRequest,
    callback: (error: grpc.ServiceError | null, response?: GetDeploymentAddressesResponse) => void
  ): grpc.ClientUnaryCall;
}

export class AppIDClient {
  private serverAddr: string;
  private client: AppIDServiceClient | null = null;
  private grpcConnection: grpc.Client | null = null;

  constructor(serverAddr: string) {
    this.serverAddr = serverAddr;
  }

  async connect(tlsConfig: tls.SecureContextOptions): Promise<void> {
    try {
      // Close existing connection if any
      if (this.grpcConnection) {
        this.grpcConnection.close();
      }

      const protoPath = path.resolve(__dirname, '../proto/appid/appid_service.proto');
      const packageDefinition = protoLoader.loadSync(protoPath, {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
      });

      const appidProto = grpc.loadPackageDefinition(packageDefinition) as any;
      const AppIDServiceClient = appidProto.appid.AppIDService;

      // Create TLS credentials
      const credentials = grpc.credentials.createSsl(
        tlsConfig.ca as Buffer,
        tlsConfig.key as Buffer,
        tlsConfig.cert as Buffer
      );

      this.grpcConnection = new AppIDServiceClient(
        this.serverAddr,
        credentials
      ) as grpc.Client;
      
      this.client = this.grpcConnection as unknown as AppIDServiceClient;
    } catch (error) {
      throw new Error(`failed to connect to AppID service: ${error}`);
    }
  }

  async getPublicKeyByAppID(appId: string): Promise<{publickey: string, protocol: string, curve: string}> {
    if (!this.client) {
      throw new Error('client not connected');
    }

    return new Promise((resolve, reject) => {
      const request: GetPublicKeyByAppIDRequest = { app_id: appId };
      
      this.client!.GetPublicKeyByAppID(request, (error: grpc.ServiceError | null, response?: GetPublicKeyByAppIDResponse) => {
        if (error) {
          reject(new Error(`failed to get public key: ${error.message}`));
        } else if (response) {
          resolve({
            publickey: response.publickey,
            protocol: response.protocol,
            curve: response.curve
          });
        } else {
          reject(new Error('no response received'));
        }
      });
    });
  }

  async getDeploymentAddresses(appId: string, timeout: number): Promise<{ deployments: { [appId: string]: DeploymentInfo }, notFound: string[], voting_sign_path?: string, required_votes?: number, enable_voting_sign?: boolean }> {
    if (!this.client) {
      throw new Error('client not connected');
    }

    return new Promise((resolve, reject) => {
      const request: GetDeploymentAddressesRequest = { app_id: appId };

      this.client!.GetDeploymentAddresses(request, (error: grpc.ServiceError | null, response?: GetDeploymentAddressesResponse) => {
        if (error) {
          reject(new Error(`failed to get deployment addresses: ${error.message}`));
        } else if (response) {
          resolve({
            deployments: response.deployments,
            notFound: response.not_found,
            voting_sign_path: (response as any).voting_sign_path,
            required_votes: (response as any).required_votes,
            enable_voting_sign: (response as any).enable_voting_sign
          });
        } else {
          reject(new Error('no response received'));
        }
      });
    });
  }

  async getDeploymentTargetsForAppIDs(appIds: string[], timeout: number): Promise<{ [appId: string]: DeploymentTarget }> {
    // For backward compatibility, make multiple calls if needed
    // In practice, this method is not used in the new voting flow
    const allDeployments: { [appId: string]: DeploymentInfo } = {};
    const allNotFound: string[] = [];
    
    for (const appId of appIds) {
      const { deployments, notFound } = await this.getDeploymentAddresses(appId, timeout);
      Object.assign(allDeployments, deployments);
      allNotFound.push(...notFound);
    }
    
    const deployments = allDeployments;
    const notFound = allNotFound;
    
    const result: { [appId: string]: DeploymentTarget } = {};
    
    // Process successful deployments
    for (const [appId, deployment] of Object.entries(deployments)) {
      if (!deployment.container_ip || !deployment.deployment_client_address) {
        console.warn(`⚠️  App ID ${appId} missing container IP or deployment client address`);
        continue;
      }
      
      // Parse the deployment client address to extract host and port
      const addressParts = deployment.deployment_client_address.split(':');
      const address = addressParts[0];
      const port = addressParts.length > 1 ? parseInt(addressParts[1], 10) : 50053; // Default voting port
      
      result[appId] = {
        appID: appId,
        address,
        port,
        containerIP: deployment.container_ip,
        deploymentClientAddress: deployment.deployment_client_address,
        votingSignPath: '', // No longer in individual deployment info
        httpBaseURL: deployment.deployment_host,
        servicePort: deployment.service_port // Container service port
      };
    }
    
    // Log not found app IDs
    for (const appId of notFound) {
      console.warn(`⚠️  App ID ${appId} not found or not deployed`);
    }
    
    return result;
  }

  // GetDeploymentTargetsForVotingSign gets deployment targets for voting sign based on a single app ID
  // It returns all target app IDs configured for the voting sign project
  async getDeploymentTargetsForVotingSign(appId: string, timeout: number): Promise<{
    deploymentTargets: { [appId: string]: DeploymentTarget };
    votingSignPath: string;
    requiredVotes: number;
    enableVotingSign: boolean;
  }> {
    const response = await this.getDeploymentAddresses(appId, timeout);

    const { deployments, notFound, voting_sign_path: votingSignPath = '', required_votes: requiredVotes = 0, enable_voting_sign: enableVotingSign = false } = response;

    const result: { [appId: string]: DeploymentTarget } = {};

    // Process successful deployments
    for (const [appId, deployment] of Object.entries(deployments)) {
      if (!deployment.container_ip || !deployment.deployment_client_address) {
        console.warn(`⚠️  App ID ${appId} missing container IP or deployment client address`);
        continue;
      }

      result[appId] = {
        appID: appId,
        containerIP: deployment.container_ip,
        deploymentClientAddress: deployment.deployment_client_address,
        votingSignPath: votingSignPath, // Use shared voting sign path
        httpBaseURL: deployment.deployment_host, // Use deployment host as HTTP base URL
        servicePort: deployment.service_port, // Container service port
        address: deployment.deployment_client_address.split(':')[0],
        port: parseInt(deployment.deployment_client_address.split(':')[1] || '50053', 10)
      };
    }

    // Log not found app IDs
    if (notFound.length > 0) {
      console.warn(`⚠️  App IDs not found or not deployed: ${notFound}`);
    }

    return {
      deploymentTargets: result,
      votingSignPath,
      requiredVotes,
      enableVotingSign
    };
  }

  close(): void {
    if (this.grpcConnection) {
      this.grpcConnection.close();
      this.grpcConnection = null;
      this.client = null;
    }
  }
}