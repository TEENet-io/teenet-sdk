// Copyright (c) 2025-2026 TEENet Technology (Hong Kong) Limited.
// Licensed under the GNU General Public License v3.0.
// See LICENSE file in the project root for full license text.

import { Client } from '@teenet/sdk';
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { URL } from 'node:url';
import { randomUUID } from 'node:crypto';

const host = process.env.DEMO_HOST || '127.0.0.1';
const port = Number(process.env.DEMO_PORT || '18090');
const serviceURL = process.env.SERVICE_URL || 'http://127.0.0.1:8089';
const appInstanceIDFromEnv = (process.env.APP_INSTANCE_ID || '').trim();
const sessionCookieName = 'demo_sid';

// Reuse one SDK instance and serialize operations to avoid approval token cross-talk.
const sharedSDK = new Client(serviceURL);
let sdkOpQueue: Promise<void> = Promise.resolve();

interface SessionState {
  approvalToken?: string;
  initiated?: Array<{
    tx_id: string;
    hash: string;
    app_instance_id: string;
    request_id: number;
    created_at: number;
  }>;
}
const sessionStore = new Map<string, SessionState>();
const bootstrapApprovalToken = (process.env.APPROVAL_TOKEN || '').trim();

function normalizeHexHash(v: unknown): string {
  const raw = typeof v === 'string' ? v.trim() : '';
  const body = raw.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(body)) return '';
  return `0x${body}`;
}

function extractPayloadHash(payload: unknown): string {
  if (!payload || typeof payload !== 'object') return '';
  const map = payload as Record<string, unknown>;
  return normalizeHexHash(map.hash) || normalizeHexHash(map.message_hash) || normalizeHexHash(map.digest);
}

function writeJSON(res: ServerResponse, code: number, body: unknown): void {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function parseCookies(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const kv = part.trim();
    if (!kv) continue;
    const idx = kv.indexOf('=');
    if (idx <= 0) continue;
    const key = kv.slice(0, idx).trim();
    const val = kv.slice(idx + 1).trim();
    out[key] = decodeURIComponent(val);
  }
  return out;
}

function ensureSession(req: IncomingMessage, res: ServerResponse): string {
  const headerSessionRaw = Array.isArray(req.headers['x-demo-session'])
    ? req.headers['x-demo-session'][0]
    : req.headers['x-demo-session'];
  const headerSession = typeof headerSessionRaw === 'string' ? headerSessionRaw.trim() : '';
  if (headerSession && /^[a-zA-Z0-9_-]{12,128}$/.test(headerSession)) {
    if (!sessionStore.has(headerSession)) {
      const state: SessionState = { initiated: [] };
      if (bootstrapApprovalToken) state.approvalToken = bootstrapApprovalToken;
      sessionStore.set(headerSession, state);
    }
    return headerSession;
  }

  const cookies = parseCookies(req.headers.cookie);
  const existing = cookies[sessionCookieName];
  if (existing && sessionStore.has(existing)) return existing;

  const sid = randomUUID().replace(/-/g, '');
  const state: SessionState = { initiated: [] };
  if (bootstrapApprovalToken) state.approvalToken = bootstrapApprovalToken;
  sessionStore.set(sid, state);
  res.setHeader('Set-Cookie', `${sessionCookieName}=${encodeURIComponent(sid)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`);
  return sid;
}

function getSessionState(sessionID: string): SessionState {
  let state = sessionStore.get(sessionID);
  if (!state) {
    state = { initiated: [] };
    if (bootstrapApprovalToken) state.approvalToken = bootstrapApprovalToken;
    sessionStore.set(sessionID, state);
  }
  if (!state.initiated) state.initiated = [];
  return state;
}

function upsertInitiated(session: SessionState, item: {
  tx_id: string;
  hash: string;
  app_instance_id: string;
  request_id: number;
}): void {
  const list = session.initiated || [];
  const idx = list.findIndex((x) => x.tx_id === item.tx_id);
  const row = { ...item, created_at: Date.now() };
  if (idx >= 0) list[idx] = row;
  else list.unshift(row);
  if (list.length > 100) list.length = 100;
  session.initiated = list;
}

async function withSDK<T>(fn: (sdk: Client) => Promise<T>): Promise<T> {
  const run = async (): Promise<T> => {
    return await fn(sharedSDK);
  };
  const resultPromise = sdkOpQueue.then(run, run);
  sdkOpQueue = resultPromise.then(() => undefined, () => undefined);
  return resultPromise;
}

async function getMyRequestsFromConsensus(approvalToken: string): Promise<Record<string, unknown>> {
  const response = await fetch(`${serviceURL}/api/requests/mine`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${approvalToken}`,
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    return {
      success: false,
      statusCode: response.status,
      error: (data as any)?.error || (data as any)?.message || `HTTP ${response.status}`,
      data,
    };
  }

  // Tolerate different upstream success envelope shapes.
  if (data && typeof data === 'object' && 'success' in (data as Record<string, unknown>)) {
    return data as Record<string, unknown>;
  }

  const raw = (data || {}) as Record<string, unknown>;
  const requests = Array.isArray((raw as any).requests)
    ? (raw as any).requests
    : Array.isArray((raw as any).approvals)
      ? (raw as any).approvals
      : [];
  return {
    success: true,
    statusCode: response.status,
    data: {
      requests,
    },
  };
}

async function getRequestByTxFromConsensus(approvalToken: string, txID: string): Promise<Record<string, unknown>> {
  const response = await fetch(`${serviceURL}/api/signature/by-tx/${encodeURIComponent(txID)}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${approvalToken}`,
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    return {
      success: false,
      statusCode: response.status,
      error: (data as any)?.error || (data as any)?.message || `HTTP ${response.status}`,
      data,
    };
  }
  return {
    success: true,
    statusCode: response.status,
    data: (data as any)?.data || data,
  };
}

function extractHashFromRecord(row: any): string {
  const direct = String(row?.hash || row?.message_hash || row?.digest || '').trim();
  if (direct) return direct;
  const payload = row?.payload;
  if (payload && typeof payload === 'object') {
    const nested = String((payload as any).hash || (payload as any).message_hash || (payload as any).digest || '').trim();
    if (nested) return nested;
  }
  if (typeof payload === 'string' && payload.trim()) {
    try {
      const parsed = JSON.parse(payload);
      const nested = String(parsed?.hash || parsed?.message_hash || parsed?.digest || '').trim();
      if (nested) return nested;
    } catch {
      // ignore invalid payload json
    }
  }
  return '';
}

async function enrichRequestsWithStatus(requests: any[]): Promise<any[]> {
  const enriched: any[] = [];
  for (const item of requests) {
    const row = { ...(item || {}) };
    const hash = String(row.hash || '').trim();
    if (!hash) {
      row.found = false;
      row.sign_status = '';
      row.required_votes = 0;
      row.signature = '';
      row.error_message = '';
      enriched.push(row);
      continue;
    }
    try {
      const status = await withSDK((sdk) => sdk.getStatus(hash));
      row.found = Boolean(status.found);
      row.sign_status = status.status || '';
      row.required_votes = status.requiredVotes || 0;
      row.signature = status.signature ? status.signature.toString('hex') : '';
      row.error_message = status.errorMessage || '';
    } catch (err) {
      row.found = false;
      row.sign_status = '';
      row.required_votes = 0;
      row.signature = '';
      row.error_message = err instanceof Error ? err.message : String(err);
    }
    enriched.push(row);
  }
  return enriched;
}

async function readJSON(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) return {};
  const raw = Buffer.concat(chunks).toString('utf-8').trim();
  if (!raw) return {};
  return JSON.parse(raw) as Record<string, unknown>;
}

function asNumber(v: unknown): number {
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && v.trim() !== '') return Number(v);
  return NaN;
}

async function serveStatic(res: ServerResponse, pathname: string): Promise<void> {
  const target = pathname === '/' ? '/index.html' : pathname;
  const fullPath = join(process.cwd(), 'public', target);

  try {
    const content = await readFile(fullPath);
    const ext = extname(fullPath).toLowerCase();
    const mime = ext === '.html'
      ? 'text/html; charset=utf-8'
      : ext === '.js'
        ? 'application/javascript; charset=utf-8'
        : 'text/plain; charset=utf-8';
    res.statusCode = 200;
    res.setHeader('Content-Type', mime);
    res.end(content);
  } catch {
    res.statusCode = 404;
    res.end('Not Found');
  }
}

async function handleAPI(req: IncomingMessage, res: ServerResponse, pathname: string, sessionID: string): Promise<boolean> {
  const session = getSessionState(sessionID);
  if (pathname === '/api/sign' && req.method === 'POST') {
    if (!appInstanceIDFromEnv) {
      return writeJSON(res, 500, { success: false, error: 'APP_INSTANCE_ID is not configured' }), true;
    }
    const body = await readJSON(req);
    const publicKeyName = String(body.public_key_name || '').trim();
    if (!publicKeyName) {
      return writeJSON(res, 400, { success: false, error: 'public_key_name is required' }), true;
    }
    const payload = body.payload;
    const payloadHash = extractPayloadHash(payload);
    let message: Buffer;
    if (payload !== undefined && payload !== null) {
      if (typeof payload === 'string') {
        const raw = payload.trim();
        if (!raw) return writeJSON(res, 400, { success: false, error: 'payload is empty' }), true;
        message = Buffer.from(raw, 'utf-8');
      } else {
        message = Buffer.from(JSON.stringify(payload), 'utf-8');
      }
    } else {
      const rawMessage = String(body.message || '').trim();
      if (!rawMessage) {
        return writeJSON(res, 400, { success: false, error: 'payload or message is required' }), true;
      }
      message = Buffer.from(rawMessage, 'utf-8');
    }

    const signRes = await withSDK(async (sdk) => {
      sdk.setDefaultAppID(appInstanceIDFromEnv);
      return await sdk.sign(message, publicKeyName);
    });
    const txID = String(signRes?.votingInfo?.txID || '').trim();
    const requestID = Number(signRes?.votingInfo?.requestID || 0);
    if (txID) {
      upsertInitiated(session, {
        tx_id: txID,
        hash: String(signRes?.votingInfo?.hash || payloadHash || '').trim(),
        app_instance_id: appInstanceIDFromEnv,
        request_id: requestID > 0 ? requestID : 0,
      });
    }

    return writeJSON(res, 200, {
      success: true,
      data: {
        app_instance_id: appInstanceIDFromEnv,
        public_key_name: publicKeyName,
        status: signRes?.votingInfo?.status || (signRes?.success ? 'signed' : 'failed'),
        hash: signRes?.votingInfo?.hash || payloadHash || '',
        request_id: signRes?.votingInfo?.requestID || 0,
        tx_id: signRes?.votingInfo?.txID || '',
        needs_voting: Boolean(signRes?.votingInfo?.needsVoting),
        sign_success: Boolean(signRes?.success),
        error: signRes?.error || '',
        error_code: signRes?.errorCode || '',
        signature: signRes?.signature ? `0x${signRes.signature.toString('hex')}` : '',
      },
    }), true;
  }

  if (pathname === '/api/login/options' && req.method === 'GET') {
    const result = await withSDK((sdk) => sdk.passkeyLoginOptions());
    return writeJSON(res, 200, result), true;
  }

  if (pathname === '/api/login/verify' && req.method === 'POST') {
    const body = await readJSON(req);
    const loginSessionID = asNumber(body.login_session_id);
    if (!Number.isFinite(loginSessionID) || loginSessionID <= 0) {
      return writeJSON(res, 400, { success: false, error: 'login_session_id is required' }), true;
    }
    const credential = body.credential ?? {};
    const result = await withSDK((sdk) => sdk.passkeyLoginVerify(Number(loginSessionID), credential));
    const token = typeof result?.data?.token === 'string' ? result.data.token.trim() : '';
    if (result?.success && token) {
      session.approvalToken = token;
    }
    return writeJSON(res, 200, result), true;
  }

  if (pathname === '/api/approvals/pending' && req.method === 'GET') {
    if (!session.approvalToken) {
      return writeJSON(res, 401, { success: false, error: 'not logged in for this browser session' }), true;
    }
    const requestURL = new URL(req.url || '/api/approvals/pending', `http://${req.headers.host || '127.0.0.1'}`);
    const appInstanceID = String(requestURL.searchParams.get('app_instance_id') || '').trim() || appInstanceIDFromEnv;
    const publicKeyName = String(requestURL.searchParams.get('public_key_name') || '').trim();
    const result = await withSDK((sdk) => sdk.approvalPending(session.approvalToken || ''));
    if (result?.success && result?.data && typeof result.data === 'object') {
      const data = result.data as Record<string, unknown>;
      const approvals = Array.isArray(data.approvals) ? data.approvals as Array<Record<string, unknown>> : [];
      const filtered = approvals.filter((item) => {
        if (appInstanceID) {
          const itemAppInstanceID = String(item?.app_instance_id || '').trim();
          if (itemAppInstanceID !== appInstanceID) return false;
        }
        if (publicKeyName) {
          const itemKeyName = String(item?.public_key_name || item?.key_name || '').trim();
          if (itemKeyName !== publicKeyName) return false;
        }
        return true;
      });
      data.approvals = filtered;
      data.total = filtered.length;
      if (data.level_progress && typeof data.level_progress === 'object' && data.level_progress !== null) {
        const source = data.level_progress as Record<string, unknown>;
        const taskIDs = new Set(filtered.map((x) => String(x?.id || '').trim()).filter(Boolean));
        const pruned: Record<string, unknown> = {};
        for (const taskID of taskIDs) {
          if (taskID in source) pruned[taskID] = source[taskID];
        }
        data.level_progress = pruned;
      }
    }
    return writeJSON(res, 200, result), true;
  }

  const requestChallengeMatch = pathname.match(/^\/api\/approvals\/request\/(\d+)\/challenge$/);
  if (requestChallengeMatch && req.method === 'GET') {
    if (!session.approvalToken) {
      return writeJSON(res, 401, { success: false, error: 'not logged in for this browser session' }), true;
    }
    const requestID = Number(requestChallengeMatch[1]);
    const result = await withSDK((sdk) => sdk.approvalRequestChallenge(requestID, session.approvalToken || ''));
    return writeJSON(res, 200, result), true;
  }

  const requestConfirmMatch = pathname.match(/^\/api\/approvals\/request\/(\d+)\/confirm$/);
  if (requestConfirmMatch && req.method === 'POST') {
    if (!session.approvalToken) {
      return writeJSON(res, 401, { success: false, error: 'not logged in for this browser session' }), true;
    }
    const requestID = Number(requestConfirmMatch[1]);
    const body = await readJSON(req);
    const result = await withSDK((sdk) => sdk.approvalRequestConfirm(requestID, body, session.approvalToken || ''));
    return writeJSON(res, 200, result), true;
  }

  const taskChallengeMatch = pathname.match(/^\/api\/approvals\/(\d+)\/challenge$/);
  if (taskChallengeMatch && req.method === 'GET') {
    if (!session.approvalToken) {
      return writeJSON(res, 401, { success: false, error: 'not logged in for this browser session' }), true;
    }
    const taskID = Number(taskChallengeMatch[1]);
    const result = await withSDK((sdk) => sdk.approvalActionChallenge(taskID, session.approvalToken || ''));
    return writeJSON(res, 200, result), true;
  }

  const taskActionMatch = pathname.match(/^\/api\/approvals\/(\d+)\/action$/);
  if (taskActionMatch && req.method === 'POST') {
    if (!session.approvalToken) {
      return writeJSON(res, 401, { success: false, error: 'not logged in for this browser session' }), true;
    }
    const taskID = Number(taskActionMatch[1]);
    const body = await readJSON(req);
    const result = await withSDK((sdk) => sdk.approvalAction(taskID, body, session.approvalToken || ''));
    return writeJSON(res, 200, result), true;
  }
  const signByTxMatch = pathname.match(/^\/api\/signature\/by-tx\/([^\/]+)$/);
  if (signByTxMatch && req.method === 'GET') {
    const txID = decodeURIComponent(signByTxMatch[1] || '').trim();
    if (!txID) {
      return writeJSON(res, 400, { success: false, error: 'tx_id is required' }), true;
    }
    if (!session.approvalToken) {
      return writeJSON(res, 401, { success: false, error: 'not logged in for this browser session' }), true;
    }
    const byTxResp = await getRequestByTxFromConsensus(session.approvalToken, txID);
    if (byTxResp?.success === false) {
      return writeJSON(res, Number((byTxResp as any)?.statusCode || 502), byTxResp), true;
    }
    const hash = extractHashFromRecord((byTxResp as any)?.data);
    if (!hash) {
      return writeJSON(res, 404, { success: false, error: 'hash not found for tx_id' }), true;
    }
    const result = await withSDK((sdk) => sdk.getStatus(hash));
    const signature = result.signature ? result.signature.toString('hex') : '';
    return writeJSON(res, 200, {
      success: true,
      data: {
        tx_id: txID,
        hash,
        found: result.found,
        status: result.status || '',
        required_votes: result.requiredVotes || 0,
        signature,
        error_message: result.errorMessage || '',
      },
    }), true;
  }

  if (pathname === '/api/requests/mine' && req.method === 'GET') {
    if (!session.approvalToken) {
      return writeJSON(res, 401, { success: false, error: 'not logged in for this browser session' }), true;
    }
    const mineResp = await getMyRequestsFromConsensus(session.approvalToken);
    if (mineResp?.success === false) {
      return writeJSON(res, Number((mineResp as any)?.statusCode || 502), mineResp), true;
    }
    const requests = Array.isArray((mineResp as any)?.data?.requests) ? (mineResp as any).data.requests : [];
    const enriched = await enrichRequestsWithStatus(requests);
    const base = (mineResp && typeof mineResp === 'object') ? mineResp as any : {};
    const data = (base.data && typeof base.data === 'object') ? { ...base.data, requests: enriched } : { requests: enriched };
    return writeJSON(res, 200, { ...base, success: true, data }), true;
  }

  return false;
}

const server = createServer(async (req, res) => {
  try {
    const sessionID = ensureSession(req, res);
    const url = new URL(req.url || '/', `http://${req.headers.host || `${host}:${port}`}`);
    const handled = await handleAPI(req, res, url.pathname, sessionID);
    if (!handled) {
      await serveStatic(res, url.pathname);
    }
  } catch (err) {
    writeJSON(res, 500, {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    });
  }
});

server.listen(port, host, () => {
  console.log(`[passkey-web-demo] http://${host}:${port}`);
  console.log(`[passkey-web-demo] SERVICE_URL=${serviceURL}`);
  console.log(`[passkey-web-demo] APP_INSTANCE_ID=${appInstanceIDFromEnv || '(missing)'}`);
});

process.on('SIGINT', () => {
  sharedSDK.close();
  server.close(() => process.exit(0));
});
