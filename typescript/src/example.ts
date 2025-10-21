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

import { Client, SignOptions, SignResult } from './index';
// @ts-ignore
import * as wtfnode from 'wtfnode';

async function main() {
  // Configuration
  const configServerAddr = 'localhost:50052'; // TEE config server address

  console.log('=== TEE DAO Key Management Client with Optimizations (v3.0) ===');

  // Create client with custom options
  const teeClient = new Client(configServerAddr, {
    cacheTTL: 5 * 60 * 1000,        // Cache public keys and deployments for 5 minutes
    maxConcurrentVotes: 10,          // Allow up to 10 concurrent voting requests
    frostTimeout: 10 * 1000,         // 10 seconds
    ecdsaTimeout: 20 * 1000,         // 20 seconds
  });

  try {
    // Set default App ID before initialization
    const appID = 'secure-messaging-app';
    teeClient.setDefaultAppID(appID);

    // Or load from environment variable (APP_ID)
    // teeClient.setDefaultAppIDFromEnv();

    // Initialize client
    await teeClient.init();

    console.log('Client initialized successfully with optimizations:');
    console.log(`  - Default App ID: ${appID}`);
    console.log(`  - Public key cache TTL: 5 minutes`);
    console.log(`  - Max concurrent votes: 10`);
    console.log(`  - TEE node failover: enabled`);

    // Example 1: Get public key (v3.0 - no AppID parameter needed)
    console.log('\n1. Get public key');

    try {
      const { publickey, protocol, curve } = await teeClient.getPublicKey();
      console.log(`Public key for app ID ${appID}:`);
      console.log(`  - Protocol: ${protocol}`);
      console.log(`  - Curve: ${curve}`);
      console.log(`  - Public Key: ${publickey}`);
    } catch (error) {
      console.error(`Failed to get public key: ${error}`);
    }

    // Example 2: Sign message (v3.0 - simplified API)
    console.log('\n2. Sign message');
    const message = new TextEncoder().encode('Hello from AppID Service!');

    let signResult: SignResult | undefined;
    try {
      signResult = await teeClient.sign(message);
      if (signResult.success && signResult.signature) {
        console.log('Signing successful!');
        console.log(`Message: ${new TextDecoder().decode(message)}`);
        console.log(`Signature: ${Buffer.from(signResult.signature).toString('hex')}`);
        console.log(`Success: ${signResult.success}`);
        if (signResult.error) {
          console.log(`Error: ${signResult.error}`);
        }
      } else {
        console.error(`Signing failed: ${signResult.error}`);
      }
    } catch (error) {
      console.error(`Signing failed: ${error}`);
    }

    // Example 3: Multi-party voting signature (v3.0)
    console.log('\n3. Multi-party voting signature example');
    const votingMessage = new TextEncoder().encode('test message for multi-party voting'); // Contains "test" to trigger approval

    console.log('Voting request:');
    console.log(`  - Message: ${new TextDecoder().decode(votingMessage)}`);
    console.log(`  - Signer App ID: ${appID}`);
    console.log(`  - Voting Enabled: auto-detected from AppID configuration`);

    // Create HTTP request body similar to signature-tool
    const requestData = {
      message: Buffer.from(votingMessage).toString('base64'),
      signer_app_id: appID,
      is_forwarded: false
    };

    // Create a mock HTTP request like signature-tool does
    const { IncomingMessage } = require('http');
    const httpReq = new IncomingMessage(null as any);
    httpReq.method = 'POST';
    httpReq.url = '/vote';
    httpReq.headers = {
      'content-type': 'application/json'
    };
    // Add body to request (simulating parsed body)
    (httpReq as any).body = JSON.stringify(requestData);

    // Make vote decision: approve if message contains "test"
    const localApproval = new TextDecoder().decode(votingMessage).toLowerCase().includes('test');
    console.log(`  - Local Approval: ${localApproval}`);

    // Sign with voting options (v3.0 - voting auto-enabled by AppID config)
    const votingOptions: SignOptions = {
      localApproval: localApproval,
      httpRequest: httpReq
    };

    let votingSignResult: SignResult | undefined;
    try {
      votingSignResult = await teeClient.sign(votingMessage, votingOptions);
      if (votingSignResult.success) {
        console.log('\nVoting signature completed!');
        console.log(`Success: ${votingSignResult.success}`);
        if (votingSignResult.signature) {
          console.log(`Signature: ${Buffer.from(votingSignResult.signature).toString('hex')}`);
        }

        // Display voting information if available
        if (votingSignResult.votingInfo) {
          console.log('\nVoting Details:');
          console.log(`  - Total Targets: ${votingSignResult.votingInfo.totalTargets}`);
          console.log(`  - Successful Votes: ${votingSignResult.votingInfo.successfulVotes}`);
          console.log(`  - Required Votes: ${votingSignResult.votingInfo.requiredVotes}`);

          console.log('\nIndividual Votes:');
          votingSignResult.votingInfo.voteDetails.forEach((vote: any, i: number) => {
            console.log(`  ${i + 1}. Client ${vote.clientId}: Success=${vote.success}`);
          });
        }

        if (votingSignResult.error) {
          console.log(`Error: ${votingSignResult.error}`);
        }
      } else {
        console.error(`Voting signature failed: ${votingSignResult.error}`);
      }
    } catch (error) {
      console.error(`Voting signature failed: ${error}`);
    }

    // Example 4: Verify signature (v3.0 - no AppID parameter needed)
    console.log('\n4. Verify signature');
    if (signResult && signResult.success && signResult.signature) {
      try {
        // Verify the signature we created in Example 2
        const isValid = await teeClient.verify(
          Buffer.from(message),
          Buffer.from(signResult.signature)
        );
        console.log(`Signature verification result: ${isValid}`);
        console.log(`  - Message: ${new TextDecoder().decode(message)}`);
        console.log(`  - Signature: ${Buffer.from(signResult.signature).toString('hex')}`);
        console.log(`  - App ID: ${appID}`);
        console.log(`  - Valid: ${isValid}`);

        // Test with wrong message
        const wrongMessage = Buffer.from('Wrong message');
        const isValidWrong = await teeClient.verify(
          wrongMessage,
          Buffer.from(signResult.signature)
        );
        console.log(`\nVerification with wrong message: ${isValidWrong} (expected false)`);
      } catch (error) {
        console.error(`Verification failed: ${error}`);
      }
    }

    // Example 5: Verify voting signature (v3.0)
    console.log('\n5. Verify voting signature');
    if (votingSignResult && votingSignResult.signature) {
      try {
        // Verify the voting signature from Example 3
        const isValid = await teeClient.verify(
          Buffer.from(votingMessage),
          Buffer.from(votingSignResult.signature)
        );
        console.log(`Voting signature verification result: ${isValid}`);
        console.log(`  - Message: ${new TextDecoder().decode(votingMessage)}`);
        console.log(`  - Signature: ${Buffer.from(votingSignResult.signature).toString('hex')}`);
        console.log(`  - App ID: ${appID}`);
        console.log(`  - Valid: ${isValid}`);
      } catch (error) {
        console.error(`Voting signature verification failed: ${error}`);
      }
    }

    console.log('\n=== Example completed ===');

  } catch (error) {
    console.error('Client initialization failed:', error);
  } finally {
    await teeClient.close();
    console.log('🏁 Example finished');
  }
}

if (require.main === module) {
  main().catch(console.error);
}