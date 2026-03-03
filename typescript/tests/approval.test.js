const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { Client } = require('../dist/index.js');

async function startJSONServer(handler) {
  const server = http.createServer(async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      res.statusCode = 500;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ error: String(err) }));
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const addr = server.address();
  return {
    server,
    baseURL: `http://127.0.0.1:${addr.port}`,
  };
}

function createClient(baseURL) {
  const client = new Client(baseURL, { requestTimeout: 3000 });
  return client;
}

test('approvalRequestInit sends POST payload and maps success', async () => {
  let requestBody = '';
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    assert.equal(req.method, 'POST');
    assert.equal(req.url, '/api/approvals/request/init');

    for await (const chunk of req) {
      requestBody += chunk.toString();
    }

    res.statusCode = 200;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ request_id: 12 }));
  });

  const client = createClient(baseURL);
  try {
    const result = await client.approvalRequestInit({ tx_id: 'tx-1' }, 'tok.1');
    assert.equal(result.success, true);
    assert.equal(result.statusCode, 200);
    assert.equal(result.data.request_id, 12);

    const body = JSON.parse(requestBody);
    assert.equal(body.tx_id, 'tx-1');
  } finally {
    client.close();
    server.close();
  }
});

test('approvalRequestChallenge sends GET path without user query', async () => {
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    assert.equal(req.method, 'GET');
    assert.equal(req.url, '/api/approvals/request/22/challenge');

    res.statusCode = 200;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ challenge: 'abc' }));
  });

  const client = createClient(baseURL);
  try {
    const result = await client.approvalRequestChallenge(22, 'tok.1');
    assert.equal(result.success, true);
    assert.equal(result.statusCode, 200);
    assert.equal(result.data.challenge, 'abc');
  } finally {
    client.close();
    server.close();
  }
});

test('approvalAction maps non-2xx with error field', async () => {
  const { server, baseURL } = await startJSONServer(async (_req, res) => {
    res.statusCode = 403;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ error: 'passkey user not in policy' }));
  });

  const client = createClient(baseURL);
  try {
    const result = await client.approvalAction(9, { action: 'APPROVE' }, 'tok.1');
    assert.equal(result.success, false);
    assert.equal(result.statusCode, 403);
    assert.equal(result.error, 'passkey user not in policy');
  } finally {
    client.close();
    server.close();
  }
});

test('approvalAction falls back to generic error when JSON has no message', async () => {
  const { server, baseURL } = await startJSONServer(async (_req, res) => {
    res.statusCode = 500;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: false }));
  });

  const client = createClient(baseURL);
  try {
    const result = await client.approvalAction(9, { action: 'APPROVE' }, 'tok.1');
    assert.equal(result.success, false);
    assert.equal(result.statusCode, 500);
    assert.equal(result.error, 'Approval request failed with status 500');
  } finally {
    client.close();
    server.close();
  }
});

test('approvalPending sends explicit bearer token header', async () => {
  let seenAuth = '';
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    if (req.url === '/api/approvals/pending') {
      seenAuth = req.headers.authorization || '';
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ approvals: [] }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  const client = createClient(baseURL);
  try {
    const pendingResult = await client.approvalPending('tok.123');
    assert.equal(pendingResult.success, true);
    assert.equal(seenAuth, 'Bearer tok.123');
  } finally {
    client.close();
    server.close();
  }
});

test('passkeyLoginWithCredential orchestrates options + verify', async () => {
  const calls = [];
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    calls.push(`${req.method} ${req.url}`);
    if (req.url === '/api/auth/passkey/options') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
        login_session_id: 77,
        options: { challenge: 'abc' },
      }));
      return;
    }
    if (req.url === '/api/auth/passkey/verify') {
      let body = '';
      for await (const chunk of req) {
        body += chunk.toString();
      }
      const parsed = JSON.parse(body);
      assert.equal(parsed.login_session_id, 77);
      assert.deepEqual(parsed.credential, { id: 'cred-1' });
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ token: 'tok.login.flow' }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  const client = createClient(baseURL);
  try {
    const result = await client.passkeyLoginWithCredential(async (options) => {
      assert.deepEqual(options, { challenge: 'abc' });
      return { id: 'cred-1' };
    });
    assert.equal(result.success, true);
    assert.deepEqual(calls, [
      'GET /api/auth/passkey/options',
      'POST /api/auth/passkey/verify',
    ]);
  } finally {
    client.close();
    server.close();
  }
});

test('approvalRequestConfirmWithCredential orchestrates challenge + confirm', async () => {
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    if (req.url === '/api/approvals/request/12/challenge') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ challenge: 'request-12' }));
      return;
    }
    if (req.url === '/api/approvals/request/12/confirm') {
      let body = '';
      for await (const chunk of req) {
        body += chunk.toString();
      }
      const parsed = JSON.parse(body);
      assert.deepEqual(parsed.credential, { id: 'confirm-cred' });
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ task_id: 88 }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  const client = createClient(baseURL);
  try {
    const result = await client.approvalRequestConfirmWithCredential(12, async (options) => {
      assert.deepEqual(options, { challenge: 'request-12' });
      return { id: 'confirm-cred' };
    }, 'tok.1');
    assert.equal(result.success, true);
    assert.equal(result.data.task_id, 88);
  } finally {
    client.close();
    server.close();
  }
});

test('approvalActionWithCredential orchestrates challenge + action', async () => {
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    if (req.url === '/api/approvals/99/challenge') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ options: { challenge: 'task-99' } }));
      return;
    }
    if (req.url === '/api/approvals/99/action') {
      let body = '';
      for await (const chunk of req) {
        body += chunk.toString();
      }
      const parsed = JSON.parse(body);
      assert.equal(parsed.action, 'APPROVE');
      assert.deepEqual(parsed.credential, { id: 'action-cred' });
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ status: 'APPROVED' }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  const client = createClient(baseURL);
  try {
    const result = await client.approvalActionWithCredential(99, 'APPROVE', async (options) => {
      assert.deepEqual(options, { challenge: 'task-99' });
      return { id: 'action-cred' };
    }, 'tok.1');
    assert.equal(result.success, true);
    assert.equal(result.data.status, 'APPROVED');
  } finally {
    client.close();
    server.close();
  }
});

test('sign decodes signed response signature with 0x prefix', async () => {
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    if (req.url === '/api/submit-request' && req.method === 'POST') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
        success: true,
        status: 'signed',
        signature: '0xabcdef',
        hash: '0xhash',
      }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  const client = createClient(baseURL);
  client.setDefaultAppID('app-1');
  try {
    const result = await client.sign(Buffer.from('hello'));
    assert.equal(result.success, true);
    assert.equal(result.signature.toString('hex'), 'abcdef');
  } finally {
    client.close();
    server.close();
  }
});

test('sign returns decode error code when signed signature hex is invalid', async () => {
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    if (req.url === '/api/submit-request' && req.method === 'POST') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
        success: true,
        status: 'signed',
        signature: '0xzz',
        hash: '0xhash',
      }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  const client = createClient(baseURL);
  client.setDefaultAppID('app-1');
  try {
    const result = await client.sign(Buffer.from('hello'));
    assert.equal(result.success, false);
    assert.equal(result.errorCode, 'SIGNATURE_DECODE_FAILED');
  } finally {
    client.close();
    server.close();
  }
});

test('sign returns invalid input when message is empty', async () => {
  const { server, baseURL } = await startJSONServer(async (_req, res) => {
    res.statusCode = 500;
    res.end();
  });
  const client = createClient(baseURL);
  client.setDefaultAppID('app-1');
  try {
    const result = await client.sign(Buffer.alloc(0));
    assert.equal(result.success, false);
    assert.equal(result.errorCode, 'INVALID_INPUT');
  } finally {
    client.close();
    server.close();
  }
});

test('sign waits pending request until signed', async () => {
  let statusCalls = 0;
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    if (req.url === '/api/submit-request' && req.method === 'POST') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
        success: true,
        status: 'pending',
        hash: '0xwait-hash',
        current_votes: 1,
        required_votes: 2,
        needs_voting: true,
      }));
      return;
    }
    if (req.url === '/api/cache/0xwait-hash' && req.method === 'GET') {
      statusCalls += 1;
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      if (statusCalls < 2) {
        res.end(JSON.stringify({
          success: true,
          found: true,
          entry: {
            hash: '0xwait-hash',
            status: 'pending',
            required_votes: 2,
            requests: {
              app1: { approved: true },
            },
          },
        }));
        return;
      }
      res.end(JSON.stringify({
        success: true,
        found: true,
        entry: {
          hash: '0xwait-hash',
          status: 'signed',
          signature: '0xabcdef',
          required_votes: 2,
          requests: {
            app1: { approved: true },
            app2: { approved: true },
          },
        },
      }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  const client = createClient(baseURL);
  client.setDefaultAppID('app-1');
  try {
    client.pendingWaitTimeout = 2000;
    const result = await client.sign(Buffer.from('hello'));
    assert.equal(result.success, true);
    assert.equal(result.signature.toString('hex'), 'abcdef');
    assert.equal(result.votingInfo.status, 'signed');
  } finally {
    client.close();
    server.close();
  }
});

test('sign returns threshold-not-met error when pending times out', async () => {
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    if (req.url === '/api/submit-request' && req.method === 'POST') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
        success: true,
        status: 'pending',
        hash: '0xtimeout-hash',
        current_votes: 1,
        required_votes: 2,
        needs_voting: true,
      }));
      return;
    }
    if (req.url === '/api/cache/0xtimeout-hash' && req.method === 'GET') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
        success: true,
        found: true,
        entry: {
          hash: '0xtimeout-hash',
          status: 'pending',
          required_votes: 2,
          requests: {
            app1: { approved: true },
          },
        },
      }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  const client = createClient(baseURL);
  client.setDefaultAppID('app-1');
  try {
    client.pendingWaitTimeout = 50;
    const result = await client.sign(Buffer.from('hello'));
    assert.equal(result.success, false);
    assert.match(result.error || '', /Threshold not met before timeout/);
    assert.equal(result.errorCode, 'THRESHOLD_TIMEOUT');
    assert.equal(result.votingInfo?.status, 'pending');
  } finally {
    client.close();
    server.close();
  }
});

test('sign maps server rejection to stable error code', async () => {
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    if (req.url === '/api/submit-request' && req.method === 'POST') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
        success: false,
        message: 'server rejected',
      }));
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  const client = createClient(baseURL);
  client.setDefaultAppID('app-1');
  try {
    const result = await client.sign(Buffer.from('hello'));
    assert.equal(result.success, false);
    assert.equal(result.errorCode, 'SIGN_REQUEST_REJECTED');
  } finally {
    client.close();
    server.close();
  }
});

test('sign maps submit network failure to stable error code', async () => {
  const { server, baseURL } = await startJSONServer(async (_req, res) => {
    res.statusCode = 200;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ success: true }));
  });

  const client = createClient(baseURL);
  client.setDefaultAppID('app-1');
  server.close();

  const result = await client.sign(Buffer.from('hello'));
  assert.equal(result.success, false);
  assert.equal(result.errorCode, 'SIGN_REQUEST_FAILED');
  client.close();
});

test('sign maps status polling network failure to stable error code', async () => {
  const { server, baseURL } = await startJSONServer(async (req, res) => {
    if (req.url === '/api/submit-request' && req.method === 'POST') {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
        success: true,
        status: 'pending',
        hash: '0xstatus-fail',
        current_votes: 1,
        required_votes: 2,
        needs_voting: true,
      }));
      return;
    }
    if (req.url === '/api/cache/0xstatus-fail' && req.method === 'GET') {
      req.socket.destroy();
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  const client = createClient(baseURL);
  client.setDefaultAppID('app-1');
  client.pendingWaitTimeout = 100;

  try {
    const result = await client.sign(Buffer.from('hello'));
    assert.equal(result.success, false);
    assert.equal(result.errorCode, 'STATUS_QUERY_FAILED');
    assert.equal(result.votingInfo?.status, 'pending');
  } finally {
    client.close();
    server.close();
  }
});
