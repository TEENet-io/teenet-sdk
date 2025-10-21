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

async function main() {
  console.log('=== TEE DAO Key Management Client with Optimizations ===');

  // Create client with custom options
  const teeClient = new Client({
    cacheTTL: 5 * 60 * 1000,        // Cache public keys and deployments for 5 minutes
    maxConcurrentVotes: 10,          // Allow up to 10 concurrent voting requests
    frostTimeout: 10 * 1000,         // 10 seconds
    ecdsaTimeout: 20 * 1000,         // 20 seconds
  });

  try {
    // Set default App ID before initialization
    const appID = 'secure-messaging-app';
    teeClient.setDefaultAppID(appID);

    // Initialize client
    await teeClient.init();

    console.log('Client initialized successfully with optimizations:');
    console.log(`  - Default App ID: ${appID}`);
    console.log(`  - Public key cache TTL: 5 minutes`);
    console.log(`  - Max concurrent votes: 10`);
    console.log(`  - TEE node failover: enabled`);

    // Example 1: Get public key
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

    // Example 2: Sign message
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

    // Example 3: Multi-party voting signature
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

    // Sign with voting options
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

    // Example 4: Verify signature
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

    // Example 5: Verify voting signature
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

    // Example 6: Test 5 concurrent signatures
    console.log('\n6. Test 5 concurrent signatures');
    await testConcurrentSignatures(teeClient);

    console.log('\n=== Example completed ===');

  } catch (error) {
    console.error('Client initialization failed:', error);
  } finally {
    await teeClient.close();
  }
}

// testConcurrentSignatures tests 5 concurrent signature operations
async function testConcurrentSignatures(teeClient: Client) {
  const numSignatures = 5;

  interface SignResult {
    id: number;
    success: boolean;
    signature?: Uint8Array;
    duration: number;
    error?: string;
  }

  console.log(`Starting ${numSignatures} concurrent signatures...`);
  const startTime = Date.now();

  // Launch concurrent signature operations
  const promises = Array.from({ length: numSignatures }, async (_, i) => {
    const id = i + 1;

    // Create unique message for each signature
    const now = new Date();
    const timeStr = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}.${now.getMilliseconds().toString().padStart(3, '0')}`;
    const message = new TextEncoder().encode(
      `Concurrent test message #${id} at ${timeStr}`
    );

    // Create HTTP request body for voting (if voting is enabled for this AppID)
    const requestData = {
      message: Buffer.from(message).toString('base64'),
      signer_app_id: teeClient.defaultAppID,
    };

    const requestBody = JSON.stringify(requestData);

    // Create a mock HTTP request
    const { IncomingMessage } = require('http');
    const httpReq = new IncomingMessage(null as any);
    httpReq.method = 'POST';
    httpReq.url = '/vote';
    httpReq.headers = {
      'content-type': 'application/json'
    };
    (httpReq as any).body = requestBody;

    // Make vote decision: approve if message contains "test"
    const localApproval = new TextDecoder().decode(message).toLowerCase().includes('test');

    // Time the signature operation
    const opStart = Date.now();
    try {
      const result = await teeClient.sign(message, {
        localApproval: localApproval,
        httpRequest: httpReq
      });
      const duration = Date.now() - opStart;

      return {
        id,
        success: result.success,
        signature: result.signature,
        duration,
        error: result.error
      } as SignResult;
    } catch (error: any) {
      const duration = Date.now() - opStart;
      return {
        id,
        success: false,
        duration,
        error: error.message || String(error)
      } as SignResult;
    }
  });

  // Wait for all operations to complete
  const results = await Promise.all(promises);

  const totalTime = Date.now() - startTime;
  const successCount = results.filter(r => r.success).length;
  const failureCount = results.filter(r => !r.success).length;
  const totalDuration = results.reduce((sum, r) => sum + r.duration, 0);
  const avgDuration = totalDuration / numSignatures;

  console.log('\nConcurrent Signature Results:');
  console.log('------------------------------');

  results.forEach(result => {
    if (result.success) {
      console.log(`✓ Signature #${result.id}: SUCCESS (Duration: ${result.duration}ms)`);
      if (result.signature) {
        console.log(`  Signature: ${Buffer.from(result.signature).toString('hex').substring(0, 32)}...`);
      }
    } else {
      console.log(`✗ Signature #${result.id}: FAILED (Error: ${result.error}, Duration: ${result.duration}ms)`);
    }
  });

  console.log('\n------------------------------');
  console.log('Concurrent Signature Summary:');
  console.log(`  Total Signatures: ${numSignatures}`);
  console.log(`  Successful: ${successCount}`);
  console.log(`  Failed: ${failureCount}`);
  console.log(`  Total Time: ${totalTime}ms`);
  console.log(`  Average Duration: ${avgDuration.toFixed(2)}ms`);
  console.log(`  Parallel Speedup: ${(totalDuration / totalTime).toFixed(2)}x`);

  // Test verification of one successful signature
  if (successCount > 0) {
    console.log('\nVerifying one of the concurrent signatures...');
    console.log('(Verification requires storing message-signature pairs)');
  }
}

if (require.main === module) {
  main().catch(console.error);
}
