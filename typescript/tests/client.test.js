// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Tests for Client class — constructor, config, getPublicKeys (caching),
// getStatus, key generation, API key operations, and admin operations.
//
// Run via: npm test  (build + node --test tests)

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { Client } = require('../dist/index.js');

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Spin up an ephemeral HTTP server on a random port.
 * The supplied handler is called for every request.
 * Returns { server, baseURL }.
 */
async function startServer(handler) {
  const server = http.createServer(async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ error: String(err) }));
      }
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const addr = server.address();
  return { server, baseURL: `http://127.0.0.1:${addr.port}` };
}

function json(res, body, status = 200) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}

/** Read the full request body as a parsed object. */
async function readBody(req) {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  return JSON.parse(raw);
}

/** A minimal bound public-key row in API snake_case. */
function apiKey(overrides = {}) {
  return {
    id: 1,
    name: 'pk1',
    key_data: '0x01020304',
    protocol: 'ecdsa',
    curve: 'secp256k1',
    threshold: 2,
    participant_count: 3,
    max_participant_count: 5,
    application_id: 10,
    created_by_instance_id: 'inst-1',
    ...overrides,
  };
}

function makeClient(baseURL, opts = {}) {
  return new Client(baseURL, { requestTimeout: 3000, ...opts });
}

// ─── Constructor & Configuration ────────────────────────────────────────────

test('constructor strips trailing slash from URL', () => {
  const c = new Client('http://example.com/');
  assert.equal(c.getServiceURL(), 'http://example.com');
});

test('constructor with no trailing slash leaves URL unchanged', () => {
  const c = new Client('http://example.com');
  assert.equal(c.getServiceURL(), 'http://example.com');
});

test('constructor defaults requestTimeout to 30000', () => {
  const c = new Client('http://x');
  assert.equal(c.getRequestTimeout(), 30000);
});

test('constructor respects custom requestTimeout', () => {
  const c = new Client('http://x', { requestTimeout: 5000 });
  assert.equal(c.getRequestTimeout(), 5000);
});

test('constructor defaults pendingWaitTimeout to 10000', () => {
  const c = new Client('http://x');
  assert.equal(c.getPendingWaitTimeout(), 10000);
});

test('constructor respects custom pendingWaitTimeout', () => {
  const c = new Client('http://x', { pendingWaitTimeout: 3000 });
  assert.equal(c.getPendingWaitTimeout(), 3000);
});

test('setDefaultAppInstanceID stores the ID', () => {
  const c = new Client('http://x');
  c.setDefaultAppInstanceID('my-instance');
  assert.equal(c.getDefaultAppInstanceID(), 'my-instance');
});

test('setDefaultAppInstanceIDFromEnv reads APP_INSTANCE_ID', () => {
  process.env.APP_INSTANCE_ID = 'env-instance-xyz';
  const c = new Client('http://x');
  c.setDefaultAppInstanceIDFromEnv();
  assert.equal(c.getDefaultAppInstanceID(), 'env-instance-xyz');
  delete process.env.APP_INSTANCE_ID;
});

test('setDefaultAppInstanceIDFromEnv throws when env var is missing', () => {
  delete process.env.APP_INSTANCE_ID;
  const c = new Client('http://x');
  assert.throws(
    () => c.setDefaultAppInstanceIDFromEnv(),
    /APP_INSTANCE_ID environment variable not set/
  );
});

test('constructor auto-reads SERVICE_URL and APP_INSTANCE_ID from env', () => {
  process.env.SERVICE_URL = 'http://auto-env:8089';
  process.env.APP_INSTANCE_ID = 'auto-env-id';
  const c = new Client();
  assert.equal(c.getServiceURL(), 'http://auto-env:8089');
  assert.equal(c.getDefaultAppInstanceID(), 'auto-env-id');
  delete process.env.SERVICE_URL;
  delete process.env.APP_INSTANCE_ID;
});

test('explicit serviceURL overrides env', () => {
  process.env.SERVICE_URL = 'http://from-env:8089';
  const c = new Client('http://explicit:8089');
  assert.equal(c.getServiceURL(), 'http://explicit:8089');
  delete process.env.SERVICE_URL;
});

test('close() is a no-op and does not throw', () => {
  const c = new Client('http://x');
  assert.doesNotThrow(() => c.close());
});

// ─── sign() — no App Instance ID ─────────────────────────────────────────────────────

test('sign() throws when no App Instance ID is set', async () => {
  const c = makeClient('http://127.0.0.1:1');
  await assert.rejects(
    () => c.sign(Buffer.from('hello'), 'pk1'),
    /App Instance ID not set/
  );
});

// ─── sign() — APPROVAL_PENDING ──────────────────────────────────────────────

test('sign() returns APPROVAL_PENDING with txID and requestID', async () => {
  const { server, baseURL } = await startServer(async (req, res) => {
    if (req.url.startsWith('/api/publickeys/')) {
      return json(res, { success: true, public_keys: [apiKey()] });
    }
    if (req.url === '/api/submit-request') {
      return json(res, {
        success: true,
        status: 'pending_approval',
        hash: '0xhash-approval',
        tx_id: 'tx-abc',
        request_id: 42,
      });
    }
    json(res, { error: 'not found' }, 404);
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-1');
  try {
    const result = await c.sign(Buffer.from('approve me'), 'pk1');
    assert.equal(result.success, false);
    assert.equal(result.errorCode, 'APPROVAL_PENDING');
    assert.equal(result.votingInfo?.txID, 'tx-abc');
    assert.equal(result.votingInfo?.requestID, 42);
  } finally {
    c.close();
    server.close();
  }
});

// ─── sign() — passkey token included in request ─────────────────────────────

test('sign() includes passkey_token in request body when provided', async () => {
  let capturedBody = null;
  const { server, baseURL } = await startServer(async (req, res) => {
    if (req.url.startsWith('/api/publickeys/')) {
      return json(res, { success: true, public_keys: [apiKey()] });
    }
    if (req.url === '/api/submit-request') {
      capturedBody = await readBody(req);
      return json(res, {
        success: true,
        status: 'signed',
        signature: 'aabbcc',
        hash: '0xhash1',
      });
    }
    json(res, {}, 404);
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-1');
  try {
    const result = await c.sign(Buffer.from('msg'), 'pk1', 'my-passkey-token');
    assert.equal(result.success, true);
    assert.equal(capturedBody.passkey_token, 'my-passkey-token');
  } finally {
    c.close();
    server.close();
  }
});

// ─── getPublicKeys() ─────────────────────────────────────────────────────────

test('getPublicKeys() throws when no App Instance ID is set', async () => {
  const c = makeClient('http://127.0.0.1:1');
  await assert.rejects(
    () => c.getPublicKeys(),
    /App Instance ID not set/
  );
});

test('getPublicKeys() maps all fields from snake_case to camelCase', async () => {
  const { server, baseURL } = await startServer(async (req, res) => {
    assert.equal(req.url, '/api/publickeys/my-app');
    json(res, {
      success: true,
      public_keys: [apiKey()],
    });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('my-app');
  try {
    const keys = await c.getPublicKeys();
    assert.equal(keys.length, 1);
    const k = keys[0];
    assert.equal(k.id, 1);
    assert.equal(k.name, 'pk1');
    assert.equal(k.keyData, '0x01020304');
    assert.equal(k.protocol, 'ecdsa');
    assert.equal(k.curve, 'secp256k1');
    assert.equal(k.threshold, 2);
    assert.equal(k.participantCount, 3);
    assert.equal(k.maxParticipantCount, 5);
    assert.equal(k.applicationId, 10);
    assert.equal(k.createdByInstanceId, 'inst-1');
  } finally {
    c.close();
    server.close();
  }
});

test('getPublicKeys() throws when server returns success:false', async () => {
  const { server, baseURL } = await startServer(async (_req, res) => {
    json(res, { success: false, error: 'key store error' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-1');
  try {
    await assert.rejects(
      () => c.getPublicKeys(),
      /key store error/
    );
  } finally {
    c.close();
    server.close();
  }
});

test('getPublicKeys() caches results — second call does not hit server', async () => {
  let callCount = 0;
  const { server, baseURL } = await startServer(async (_req, res) => {
    callCount++;
    json(res, { success: true, public_keys: [apiKey()] });
  });
  // Use a long TTL so the cache is definitely alive
  const c = makeClient(baseURL, { keyCacheTTL: 60000 });
  c.setDefaultAppInstanceID('app-cache');
  try {
    await c.getPublicKeys();
    await c.getPublicKeys();
    assert.equal(callCount, 1, 'server should only be hit once due to caching');
  } finally {
    c.close();
    server.close();
  }
});

test('invalidateKeyCache() clears cache — next call hits server again', async () => {
  let callCount = 0;
  const { server, baseURL } = await startServer(async (_req, res) => {
    callCount++;
    json(res, { success: true, public_keys: [apiKey()] });
  });
  const c = makeClient(baseURL, { keyCacheTTL: 60000 });
  c.setDefaultAppInstanceID('app-inv');
  try {
    await c.getPublicKeys();
    assert.equal(callCount, 1);
    c.invalidateKeyCache();
    await c.getPublicKeys();
    assert.equal(callCount, 2, 'server should be hit again after cache invalidation');
  } finally {
    c.close();
    server.close();
  }
});

test('getPublicKeys() with keyCacheTTL=-1 always hits server', async () => {
  let callCount = 0;
  const { server, baseURL } = await startServer(async (_req, res) => {
    callCount++;
    json(res, { success: true, public_keys: [apiKey()] });
  });
  const c = makeClient(baseURL, { keyCacheTTL: -1 });
  c.setDefaultAppInstanceID('app-nocache');
  try {
    await c.getPublicKeys();
    await c.getPublicKeys();
    assert.equal(callCount, 2, 'server should be hit every time when caching is disabled');
  } finally {
    c.close();
    server.close();
  }
});

// ─── getPublicKeys() URL-encoding ────────────────────────────────────────────

test('getPublicKeys() URL-encodes the app instance ID', async () => {
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenURL = req.url;
    json(res, { success: true, public_keys: [] });
  });
  const c = makeClient(baseURL, { keyCacheTTL: -1 });
  c.setDefaultAppInstanceID('app/with spaces');
  try {
    await c.getPublicKeys();
    assert.equal(seenURL, '/api/publickeys/app%2Fwith%20spaces');
  } finally {
    c.close();
    server.close();
  }
});

// ─── getStatus() ─────────────────────────────────────────────────────────────

test('getStatus() throws for empty hash', async () => {
  const c = makeClient('http://127.0.0.1:1');
  await assert.rejects(
    () => c.getStatus(''),
    /hash is required/
  );
});

test('getStatus() returns found:false when entry is absent', async () => {
  const { server, baseURL } = await startServer(async (_req, res) => {
    json(res, { success: true, found: false, message: 'not found' });
  });
  const c = makeClient(baseURL);
  try {
    const status = await c.getStatus('0xmissing');
    assert.equal(status.found, false);
    assert.equal(status.hash, '0xmissing');
    assert.equal(status.status, 'not_found');
    assert.equal(status.currentVotes, 0);
    assert.equal(status.requiredVotes, 0);
  } finally {
    c.close();
    server.close();
  }
});

test('getStatus() returns found:true and counts approved votes', async () => {
  const { server, baseURL } = await startServer(async (req, res) => {
    assert.equal(req.url, '/api/cache/0xabc123');
    json(res, {
      success: true,
      found: true,
      entry: {
        hash: '0xabc123',
        status: 'signed',
        signature: 'deadbeef',
        required_votes: 3,
        requests: {
          node1: { approved: true },
          node2: { approved: true },
          node3: { approved: false },
        },
      },
    });
  });
  const c = makeClient(baseURL);
  try {
    const status = await c.getStatus('0xabc123');
    assert.equal(status.found, true);
    assert.equal(status.hash, '0xabc123');
    assert.equal(status.status, 'signed');
    assert.equal(status.currentVotes, 2);
    assert.equal(status.requiredVotes, 3);
    assert.ok(status.signature instanceof Buffer);
    assert.equal(status.signature.toString('hex'), 'deadbeef');
  } finally {
    c.close();
    server.close();
  }
});

test('getStatus() URL-encodes the hash', async () => {
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenURL = req.url;
    json(res, { success: true, found: false });
  });
  const c = makeClient(baseURL);
  try {
    await c.getStatus('hash/with spaces');
    assert.equal(seenURL, '/api/cache/hash%2Fwith%20spaces');
  } finally {
    c.close();
    server.close();
  }
});

test('getStatus() surfaces error_message from entry', async () => {
  const { server, baseURL } = await startServer(async (_req, res) => {
    json(res, {
      success: true,
      found: true,
      entry: {
        hash: '0xerr',
        status: 'failed',
        required_votes: 2,
        error_message: 'request rejected',
      },
    });
  });
  const c = makeClient(baseURL);
  try {
    const status = await c.getStatus('0xerr');
    assert.equal(status.status, 'failed');
    assert.equal(status.errorMessage, 'request rejected');
  } finally {
    c.close();
    server.close();
  }
});

// ─── generateKey() unified entry point ────────────────────────────────────────

test('generateKey(Schnorr, ed25519) sends correct protocol to server', async () => {
  let capturedBody = null;
  const { server, baseURL } = await startServer(async (req, res) => {
    capturedBody = await readBody(req);
    json(res, {
      success: true,
      message: 'generated',
      public_key: apiKey({ protocol: 'schnorr', curve: 'ed25519' }),
    });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-gen');
  try {
    const result = await c.generateKey('schnorr', 'ed25519');
    assert.equal(result.success, true);
    assert.equal(capturedBody.protocol, 'schnorr');
    assert.equal(capturedBody.curve, 'ed25519');
    assert.equal(capturedBody.app_instance_id, 'app-gen');
  } finally {
    c.close();
    server.close();
  }
});

test('generateKey(ECDSA, secp256k1) sends correct protocol to server', async () => {
  let capturedBody = null;
  const { server, baseURL } = await startServer(async (req, res) => {
    capturedBody = await readBody(req);
    json(res, {
      success: true,
      message: 'ecdsa key created',
      public_key: apiKey({ protocol: 'ecdsa', curve: 'secp256k1' }),
    });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-ecdsa');
  try {
    const result = await c.generateKey('ecdsa', 'secp256k1');
    assert.equal(result.success, true);
    assert.equal(capturedBody.protocol, 'ecdsa');
    assert.equal(capturedBody.curve, 'secp256k1');
    assert.equal(result.message, 'ecdsa key created');
  } finally {
    c.close();
    server.close();
  }
});

test('generateKey() maps all public key fields', async () => {
  const { server, baseURL } = await startServer(async (_req, res) => {
    json(res, {
      success: true,
      message: 'ok',
      public_key: {
        id: 7,
        name: 'frost-key',
        key_data: '0xdeadbeef',
        protocol: 'schnorr',
        curve: 'secp256k1',
        threshold: 3,
        participant_count: 5,
        max_participant_count: 7,
        application_id: 99,
        created_by_instance_id: 'inst-gen',
      },
    });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-gen2');
  try {
    const result = await c.generateKey('schnorr', 'secp256k1');
    const pk = result.publicKey;
    assert.equal(pk.id, 7);
    assert.equal(pk.name, 'frost-key');
    assert.equal(pk.keyData, '0xdeadbeef');
    assert.equal(pk.threshold, 3);
    assert.equal(pk.participantCount, 5);
    assert.equal(pk.maxParticipantCount, 7);
    assert.equal(pk.applicationId, 99);
    assert.equal(pk.createdByInstanceId, 'inst-gen');
  } finally {
    c.close();
    server.close();
  }
});

test('generateKey() returns failure when server returns success:false', async () => {
  const { server, baseURL } = await startServer(async (_req, res) => {
    json(res, { success: false, message: 'DKG failed' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-fail');
  try {
    const result = await c.generateKey('ecdsa', 'secp256r1');
    assert.equal(result.success, false);
    assert.equal(result.message, 'DKG failed');
  } finally {
    c.close();
    server.close();
  }
});

test('generateKey(ECDSA) throws when no App Instance ID is set', async () => {
  const c = makeClient('http://127.0.0.1:1');
  await assert.rejects(
    () => c.generateKey('ecdsa', 'secp256k1'),
    /App Instance ID not set/
  );
});

test('generateKey(EdDSA, ed25519) routes to schnorr backend path', async () => {
  let capturedBody = null;
  const { server, baseURL } = await startServer(async (req, res) => {
    capturedBody = await readBody(req);
    json(res, {
      success: true,
      message: 'ok',
      public_key: apiKey({ protocol: 'schnorr', curve: 'ed25519' }),
    });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-eddsa');
  try {
    const result = await c.generateKey('eddsa', 'ed25519');
    assert.equal(result.success, true);
    // EdDSA is a semantic alias — backend must still receive "schnorr".
    assert.equal(capturedBody.protocol, 'schnorr');
    assert.equal(capturedBody.curve, 'ed25519');
  } finally {
    c.close();
    server.close();
  }
});

test('generateKey(EdDSA, secp256k1) rejects before any network call', async () => {
  const c = makeClient('http://127.0.0.1:1');
  c.setDefaultAppInstanceID('app-x');
  await assert.rejects(
    () => c.generateKey('eddsa', 'secp256k1'),
    /EdDSA.*only.*ed25519/
  );
});

test('generateKey(SchnorrBIP340, secp256k1) routes to schnorr backend path', async () => {
  let capturedBody = null;
  const { server, baseURL } = await startServer(async (req, res) => {
    capturedBody = await readBody(req);
    json(res, {
      success: true,
      message: 'ok',
      public_key: apiKey({ protocol: 'schnorr', curve: 'secp256k1' }),
    });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-taproot');
  try {
    const result = await c.generateKey('schnorr-bip340', 'secp256k1');
    assert.equal(result.success, true);
    // SchnorrBIP340 is a semantic alias — backend still receives "schnorr".
    assert.equal(capturedBody.protocol, 'schnorr');
    assert.equal(capturedBody.curve, 'secp256k1');
  } finally {
    c.close();
    server.close();
  }
});

test('generateKey(SchnorrBIP340, ed25519) rejects before any network call', async () => {
  const c = makeClient('http://127.0.0.1:1');
  c.setDefaultAppInstanceID('app-x');
  await assert.rejects(
    () => c.generateKey('schnorr-bip340', 'ed25519'),
    /SchnorrBIP340.*only.*secp256k1/
  );
});

test('generateKey() rejects unsupported protocol', async () => {
  const c = makeClient('http://127.0.0.1:1');
  c.setDefaultAppInstanceID('app-x');
  await assert.rejects(
    () => c.generateKey('rsa', 'secp256k1'),
    /invalid protocol/
  );
});

// ─── getAPIKey() ──────────────────────────────────────────────────────────────

test('getAPIKey() returns key value from server', async () => {
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenURL = req.url;
    json(res, { success: true, api_key: 'secret-key-value' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-ak');
  try {
    const result = await c.getAPIKey('my-key');
    assert.equal(result.success, true);
    assert.equal(result.apiKey, 'secret-key-value');
    assert.ok(seenURL.startsWith('/api/apikey/my-key'));
    assert.ok(seenURL.includes('app_instance_id=app-ak'));
  } finally {
    c.close();
    server.close();
  }
});

test('getAPIKey() URL-encodes special chars in key name', async () => {
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenURL = req.url;
    json(res, { success: true, api_key: 'val' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-special');
  try {
    await c.getAPIKey('key/with spaces');
    assert.ok(seenURL.startsWith('/api/apikey/key%2Fwith%20spaces'), `unexpected URL: ${seenURL}`);
  } finally {
    c.close();
    server.close();
  }
});

test('getAPIKey() returns failure when server returns success:false', async () => {
  const { server, baseURL } = await startServer(async (_req, res) => {
    json(res, { success: false, error: 'not found' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-ak2');
  try {
    const result = await c.getAPIKey('missing');
    assert.equal(result.success, false);
    assert.equal(result.error, 'not found');
  } finally {
    c.close();
    server.close();
  }
});

test('getAPIKey() throws when no App Instance ID is set', async () => {
  const c = makeClient('http://127.0.0.1:1');
  await assert.rejects(
    () => c.getAPIKey('k'),
    /App Instance ID not set/
  );
});

// ─── signWithAPISecret() ─────────────────────────────────────────────────────

test('signWithAPISecret() sends correct body and returns signature', async () => {
  let capturedBody = null;
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenURL = req.url;
    capturedBody = await readBody(req);
    json(res, { success: true, signature: 'aabbccdd', algorithm: 'HMAC-SHA256' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-sign');
  try {
    const msg = Buffer.from('sign me');
    const result = await c.signWithAPISecret('my-secret', msg);
    assert.equal(result.success, true);
    assert.equal(result.signature, 'aabbccdd');
    assert.equal(result.algorithm, 'HMAC-SHA256');
    assert.equal(seenURL, '/api/apikey/my-secret/sign');
    assert.equal(capturedBody.app_instance_id, 'app-sign');
    assert.equal(capturedBody.message, msg.toString('hex'));
  } finally {
    c.close();
    server.close();
  }
});

test('signWithAPISecret() URL-encodes key name', async () => {
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenURL = req.url;
    json(res, { success: true, signature: 'xx', algorithm: 'HMAC-SHA256' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-enc');
  try {
    await c.signWithAPISecret('key/special name', Buffer.from('m'));
    assert.equal(seenURL, '/api/apikey/key%2Fspecial%20name/sign');
  } finally {
    c.close();
    server.close();
  }
});

test('signWithAPISecret() returns failure when server returns success:false', async () => {
  const { server, baseURL } = await startServer(async (_req, res) => {
    json(res, { success: false, error: 'secret not found' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-fail2');
  try {
    const result = await c.signWithAPISecret('bad-key', Buffer.from('m'));
    assert.equal(result.success, false);
    assert.equal(result.error, 'secret not found');
  } finally {
    c.close();
    server.close();
  }
});

// ─── Admin: invitePasskeyUser() ──────────────────────────────────────────────

test('invitePasskeyUser() sends correct body and maps invite result', async () => {
  let capturedBody = null;
  const { server, baseURL } = await startServer(async (req, res) => {
    assert.equal(req.url, '/api/admin/passkey/invite');
    assert.equal(req.method, 'POST');
    capturedBody = await readBody(req);
    json(res, {
      invite_token: 'tok-xyz',
      register_url: 'https://example.com/register',
      expires_at: '2030-01-01T00:00:00Z',
    });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-admin');
  try {
    const result = await c.invitePasskeyUser({
      displayName: 'Alice',
      applicationId: 5,
      expiresInSeconds: 3600,
    });
    assert.equal(result.success, true);
    assert.equal(result.inviteToken, 'tok-xyz');
    assert.equal(result.registerUrl, 'https://example.com/register');
    assert.equal(result.expiresAt, '2030-01-01T00:00:00Z');
    assert.equal(capturedBody.display_name, 'Alice');
    assert.equal(capturedBody.application_id, 5);
    assert.equal(capturedBody.expires_in_seconds, 3600);
    assert.equal(capturedBody.app_instance_id, 'app-admin');
  } finally {
    c.close();
    server.close();
  }
});

test('invitePasskeyUser() returns error when no App Instance ID is set', async () => {
  const c = makeClient('http://127.0.0.1:1');
  const result = await c.invitePasskeyUser({ displayName: 'Bob' });
  assert.equal(result.success, false);
  assert.match(result.error || '', /App Instance ID not set/);
});

// ─── Admin: listPasskeyUsers() ────────────────────────────────────────────────

test('listPasskeyUsers() returns mapped user list', async () => {
  const { server, baseURL } = await startServer(async (req, res) => {
    assert.ok(req.url.startsWith('/api/admin/passkey/users'));
    json(res, {
      users: [
        { id: 1, display_name: 'Alice', user_handle: 'hdl-1', application_id: 5, created_at: '2025-01-01' },
        { id: 2, display_name: 'Bob' },
      ],
      total: 2,
      page: 1,
      limit: 20,
    });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-lu');
  try {
    const result = await c.listPasskeyUsers(1, 20);
    assert.equal(result.success, true);
    assert.equal(result.total, 2);
    assert.equal(result.page, 1);
    assert.equal(result.limit, 20);
    assert.equal(result.users.length, 2);
    assert.equal(result.users[0].id, 1);
    assert.equal(result.users[0].displayName, 'Alice');
    assert.equal(result.users[0].userHandle, 'hdl-1');
    assert.equal(result.users[0].applicationId, 5);
    assert.equal(result.users[0].createdAt, '2025-01-01');
    assert.equal(result.users[1].id, 2);
    assert.equal(result.users[1].displayName, 'Bob');
  } finally {
    c.close();
    server.close();
  }
});

test('listPasskeyUsers() includes page/limit query params when non-zero', async () => {
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenURL = req.url;
    json(res, { users: [], total: 0, page: 2, limit: 10 });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-pager');
  try {
    await c.listPasskeyUsers(2, 10);
    assert.ok(seenURL.includes('page=2'), `expected page=2 in ${seenURL}`);
    assert.ok(seenURL.includes('limit=10'), `expected limit=10 in ${seenURL}`);
  } finally {
    c.close();
    server.close();
  }
});

// ─── Admin: deletePasskeyUser() ───────────────────────────────────────────────

test('deletePasskeyUser() calls DELETE with correct path', async () => {
  let seenMethod = '';
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenMethod = req.method;
    seenURL = req.url;
    json(res, { message: 'deleted' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-del');
  try {
    const result = await c.deletePasskeyUser(7);
    assert.equal(result.success, true);
    assert.equal(seenMethod, 'DELETE');
    assert.ok(seenURL.startsWith('/api/admin/passkey/users/7'), `unexpected URL: ${seenURL}`);
  } finally {
    c.close();
    server.close();
  }
});

// ─── Admin: listAuditRecords() ────────────────────────────────────────────────

test('listAuditRecords() maps all 15 fields correctly', async () => {
  const { server, baseURL } = await startServer(async (_req, res) => {
    json(res, {
      records: [
        {
          id: 100,
          task_id: 200,
          request_session_id: 300,
          event_type: 'SIGN_REQUEST',
          action: 'approve',
          status: 'completed',
          actor_passkey_user_id: 5,
          actor_display_name: 'Alice',
          tx_id: 'tx-001',
          hash: '0xfeed',
          signature: '0xsig',
          app_instance_id: 'inst-99',
          details: 'approved by quorum',
          error_message: '',
          created_at: '2025-06-01T12:00:00Z',
        },
      ],
      total: 1,
      page: 0,
      limit: 0,
    });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-audit');
  try {
    const result = await c.listAuditRecords();
    assert.equal(result.success, true);
    assert.equal(result.records.length, 1);
    const r = result.records[0];
    assert.equal(r.id, 100);
    assert.equal(r.taskId, 200);
    assert.equal(r.requestSessionId, 300);
    assert.equal(r.eventType, 'SIGN_REQUEST');
    assert.equal(r.action, 'approve');
    assert.equal(r.status, 'completed');
    assert.equal(r.actorPasskeyUserId, 5);
    assert.equal(r.actorDisplayName, 'Alice');
    assert.equal(r.txId, 'tx-001');
    assert.equal(r.hash, '0xfeed');
    assert.equal(r.signature, '0xsig');
    assert.equal(r.appInstanceId, 'inst-99');
    assert.equal(r.details, 'approved by quorum');
    assert.equal(r.createdAt, '2025-06-01T12:00:00Z');
  } finally {
    c.close();
    server.close();
  }
});

// ─── Admin: upsertPermissionPolicy() ─────────────────────────────────────────

test('upsertPermissionPolicy() sends correct body with levels', async () => {
  let capturedBody = null;
  let seenMethod = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenMethod = req.method;
    capturedBody = await readBody(req);
    json(res, { success: true });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-policy');
  try {
    const result = await c.upsertPermissionPolicy({
      publicKeyName: 'pk-threshold',
      enabled: true,
      timeoutSeconds: 300,
      levels: [
        { levelIndex: 0, threshold: 2, memberIds: [1, 2, 3] },
      ],
    });
    assert.equal(result.success, true);
    assert.equal(seenMethod, 'PUT');
    assert.equal(capturedBody.app_instance_id, 'app-policy');
    assert.equal(capturedBody.public_key_name, 'pk-threshold');
    assert.equal(capturedBody.enabled, true);
    assert.equal(capturedBody.timeout_seconds, 300);
    assert.equal(capturedBody.levels.length, 1);
    assert.equal(capturedBody.levels[0].level_index, 0);
    assert.equal(capturedBody.levels[0].threshold, 2);
    assert.deepEqual(capturedBody.levels[0].member_ids, [1, 2, 3]);
  } finally {
    c.close();
    server.close();
  }
});

// ─── Admin: deletePermissionPolicy() ─────────────────────────────────────────

test('deletePermissionPolicy() sends DELETE to /api/admin/policy', async () => {
  let seenMethod = '';
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenMethod = req.method;
    seenURL = req.url;
    json(res, { success: true });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-delpol');
  try {
    const result = await c.deletePermissionPolicy('my-key');
    assert.equal(result.success, true);
    assert.equal(seenMethod, 'DELETE');
    assert.ok(seenURL.startsWith('/api/admin/policy'), `unexpected URL: ${seenURL}`);
    assert.ok(seenURL.includes('public_key_name=my-key'));
    assert.ok(seenURL.includes('app_instance_id=app-delpol'));
  } finally {
    c.close();
    server.close();
  }
});

// ─── Admin: deletePublicKey() ─────────────────────────────────────────────────

test('deletePublicKey() sends DELETE to /api/admin/publickeys/:name', async () => {
  let seenMethod = '';
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenMethod = req.method;
    seenURL = req.url;
    json(res, { message: 'removed' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-dpk');
  try {
    const result = await c.deletePublicKey('stale-key');
    assert.equal(result.success, true);
    assert.equal(seenMethod, 'DELETE');
    assert.ok(seenURL.startsWith('/api/admin/publickeys/stale-key'), `unexpected URL: ${seenURL}`);
  } finally {
    c.close();
    server.close();
  }
});

// ─── Admin: createAPIKey() ────────────────────────────────────────────────────

test('createAPIKey() sends all fields and maps result', async () => {
  let capturedBody = null;
  const { server, baseURL } = await startServer(async (req, res) => {
    assert.equal(req.url, '/api/admin/apikeys');
    assert.equal(req.method, 'POST');
    capturedBody = await readBody(req);
    json(res, {
      id: 55,
      name: 'exchange-key',
      has_api_key: true,
      has_api_secret: true,
    });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-cak');
  try {
    const result = await c.createAPIKey({
      name: 'exchange-key',
      description: 'Binance integration',
      apiKey: 'ak-value',
      apiSecret: 'as-value',
    });
    assert.equal(result.success, true);
    assert.equal(result.id, 55);
    assert.equal(result.name, 'exchange-key');
    assert.equal(result.hasApiKey, true);
    assert.equal(result.hasApiSecret, true);
    assert.equal(capturedBody.name, 'exchange-key');
    assert.equal(capturedBody.description, 'Binance integration');
    assert.equal(capturedBody.api_key, 'ak-value');
    assert.equal(capturedBody.api_secret, 'as-value');
    assert.equal(capturedBody.app_instance_id, 'app-cak');
  } finally {
    c.close();
    server.close();
  }
});

// ─── Admin: deleteAPIKey() ────────────────────────────────────────────────────

test('deleteAPIKey() sends DELETE to /api/admin/apikeys/:name', async () => {
  let seenMethod = '';
  let seenURL = '';
  const { server, baseURL } = await startServer(async (req, res) => {
    seenMethod = req.method;
    seenURL = req.url;
    json(res, { message: 'ok' });
  });
  const c = makeClient(baseURL);
  c.setDefaultAppInstanceID('app-dak');
  try {
    const result = await c.deleteAPIKey('old-secret');
    assert.equal(result.success, true);
    assert.equal(seenMethod, 'DELETE');
    assert.ok(seenURL.startsWith('/api/admin/apikeys/old-secret'), `unexpected URL: ${seenURL}`);
  } finally {
    c.close();
    server.close();
  }
});

// ─── Response size guard ──────────────────────────────────────────────────────

test('large content-length header causes fetch to throw', async () => {
  const { server, baseURL } = await startServer(async (_req, res) => {
    // Set a content-length that exceeds MAX_RESPONSE_SIZE (10MB)
    res.writeHead(200, {
      'content-type': 'application/json',
      'content-length': String(11 * 1024 * 1024),
    });
    // Don't send the body — the size check happens before body reading
    res.end(JSON.stringify({ success: true, public_keys: [] }));
  });
  const c = makeClient(baseURL, { keyCacheTTL: -1 });
  c.setDefaultAppInstanceID('app-big');
  try {
    await assert.rejects(
      () => c.getPublicKeys(),
      /Response too large/
    );
  } finally {
    c.close();
    server.close();
  }
});
