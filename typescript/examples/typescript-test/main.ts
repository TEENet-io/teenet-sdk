// TEENet SDK TypeScript Test Program
// Tests the mock server functionality
//
// Usage:
//   1. Start mock server: cd mock-server && ./start.sh
//   2. Run tests: cd examples/typescript-test && npm install && npm test

import { Client, Curve, Protocol, verifyHMACSHA256 } from '@teenet/sdk';
import { createHmac } from 'crypto';

const serverURL = process.env.MOCK_SERVER_URL || 'http://localhost:8089';

interface TestCase {
  name: string;
  appID: string;
  protocol: string;
  curve: string;
}

async function main() {
  console.log('='.repeat(60));
  console.log('  TEENet SDK TypeScript Mock Server Test');
  console.log('='.repeat(60));
  console.log(`  Server: ${serverURL}`);
  console.log('='.repeat(60));
  console.log();

  const testCases: TestCase[] = [
    { name: 'ED25519 Schnorr', appID: 'test-schnorr-ed25519', protocol: 'schnorr', curve: 'ed25519' },
    { name: 'SECP256K1 ECDSA', appID: 'test-ecdsa-secp256k1', protocol: 'ecdsa', curve: 'secp256k1' },
    { name: 'SECP256K1 Schnorr', appID: 'test-schnorr-secp256k1', protocol: 'schnorr', curve: 'secp256k1' },
    { name: 'SECP256R1 ECDSA', appID: 'test-ecdsa-secp256r1', protocol: 'ecdsa', curve: 'secp256r1' },
    { name: 'Ethereum Wallet', appID: 'ethereum-wallet-app', protocol: 'ecdsa', curve: 'secp256k1' },
  ];

  let passed = 0;
  let failed = 0;

  // Test signing and verification
  for (const tc of testCases) {
    console.log(`Test ${tc.name} (${tc.protocol}/${tc.curve})`);
    console.log(`   App ID: ${tc.appID}`);

    try {
      await testSignAndVerify(serverURL, tc.appID);
      console.log('   PASSED');
      passed++;
    } catch (err) {
      console.log(`   FAILED: ${err}`);
      failed++;
    }
    console.log();
  }

  // Test key generation
  console.log('Test Key Generation');
  try {
    await testKeyGeneration(serverURL);
    console.log('   PASSED');
    passed++;
  } catch (err) {
    console.log(`   FAILED: ${err}`);
    failed++;
  }
  console.log();

  // Test API Key
  console.log('Test API Key');
  try {
    await testAPIKey(serverURL);
    console.log('   PASSED');
    passed++;
  } catch (err) {
    console.log(`   FAILED: ${err}`);
    failed++;
  }
  console.log();

  // Test API Secret signing
  console.log('Test API Secret Sign');
  try {
    await testAPISecretSign(serverURL);
    console.log('   PASSED');
    passed++;
  } catch (err) {
    console.log(`   FAILED: ${err}`);
    failed++;
  }
  console.log();

  // Summary
  console.log('='.repeat(60));
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(60));

  if (failed > 0) {
    process.exit(1);
  }
}

async function testSignAndVerify(serverURL: string, appID: string): Promise<void> {
  const client = new Client(serverURL);
  client.setDefaultAppID(appID);

  try {
    const message = Buffer.from('Hello, TEENet! This is a test message.');

    // Get public key
    const keyInfo = await client.getPublicKey();
    console.log(`   Public Key: ${keyInfo.publicKey.slice(0, 16)}...${keyInfo.publicKey.slice(-8)}`);
    console.log(`   Protocol: ${keyInfo.protocol}, Curve: ${keyInfo.curve}`);

    // Sign
    const result = await client.sign(message);
    if (!result.success) {
      throw new Error(`sign returned failure: ${result.error}`);
    }
    console.log(`   Signature: ${result.signature.toString('hex').slice(0, 16)}... (${result.signature.length} bytes)`);

    // Verify
    const valid = await client.verify(message, result.signature);
    if (!valid) {
      throw new Error('signature verification failed');
    }
    console.log('   Verify: OK');
  } finally {
    client.close();
  }
}

async function testKeyGeneration(serverURL: string): Promise<void> {
  const client = new Client(serverURL);
  client.setDefaultAppID('new-test-app');

  try {
    const keyCases = [
      { name: 'ECDSA secp256k1', protocol: Protocol.ECDSA, curve: Curve.SECP256K1 },
      { name: 'ECDSA secp256r1', protocol: Protocol.ECDSA, curve: Curve.SECP256R1 },
      { name: 'Schnorr secp256k1', protocol: Protocol.Schnorr, curve: Curve.SECP256K1 },
      { name: 'Schnorr ed25519', protocol: Protocol.Schnorr, curve: Curve.ED25519 },
    ];

    for (const kc of keyCases) {
      let result;
      if (kc.protocol === Protocol.ECDSA) {
        result = await client.generateECDSAKey(kc.curve);
      } else {
        result = await client.generateSchnorrKey(kc.curve);
      }

      if (!result.success) {
        throw new Error(`generate ${kc.name} key returned failure: ${result.message}`);
      }

      console.log(`   ${kc.name}: ID=${result.publicKey.id}, Key=${result.publicKey.keyData.slice(0, 16)}...${result.publicKey.keyData.slice(-8)}`);

      // Test signing with generated key
      const pubKeyBytes = Buffer.from(result.publicKey.keyData, 'hex');
      const message = Buffer.from('Test message for generated key');
      const signResult = await client.sign(message, pubKeyBytes);

      if (!signResult.success) {
        throw new Error(`sign with ${kc.name} key returned failure: ${signResult.error}`);
      }

      // Verify the signature
      const valid = client.verifyWithPublicKey(message, signResult.signature, pubKeyBytes, kc.protocol, kc.curve);
      if (!valid) {
        throw new Error(`${kc.name} signature verification failed`);
      }
      console.log(`   ${kc.name}: Sign & Verify OK`);
    }
  } finally {
    client.close();
  }
}

async function testAPIKey(serverURL: string): Promise<void> {
  const client = new Client(serverURL);
  client.setDefaultAppID('test-ecdsa-secp256k1');

  try {
    const result = await client.getAPIKey('test-api-key');
    if (!result.success) {
      throw new Error(`get API key returned failure: ${result.error}`);
    }

    console.log(`   API Key: ${result.apiKey}`);
  } finally {
    client.close();
  }
}

async function testAPISecretSign(serverURL: string): Promise<void> {
  const client = new Client(serverURL);
  client.setDefaultAppID('test-ecdsa-secp256k1');

  try {
    const message = Buffer.from('Message to sign with API secret');
    const result = await client.signWithAPISecret('test-api-secret', message);

    if (!result.success) {
      throw new Error(`API secret sign returned failure: ${result.error}`);
    }

    console.log(`   Algorithm: ${result.algorithm}`);
    console.log(`   Signature: ${result.signature.slice(0, 16)}... (${result.signature.length / 2} bytes)`);

    // Verify HMAC signature locally
    // Mock server uses secret "secret_test-ecdsa-secp256k1_abcdef"
    const secret = Buffer.from('secret_test-ecdsa-secp256k1_abcdef');
    const signatureBytes = Buffer.from(result.signature, 'hex');

    const valid = verifyHMACSHA256(message, secret, signatureBytes);
    if (!valid) {
      throw new Error('HMAC signature verification failed');
    }
    console.log('   Verify: OK');
  } finally {
    client.close();
  }
}

main().catch(console.error);
