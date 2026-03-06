import React, { useMemo, useState } from 'https://esm.sh/react@18.3.1';
import { createRoot } from 'https://esm.sh/react-dom@18.3.1/client';
import htm from 'https://esm.sh/htm@3.1.1';

const html = htm.bind(React.createElement);

function getApiBasePath() {
  const p = window.location.pathname || '/';
  if (p === '/') return '';
  const segs = p.split('/').filter(Boolean);
  const last = segs.length ? segs[segs.length - 1] : '';
  if (last.includes('.')) return segs.length <= 1 ? '/' : `/${segs.slice(0, -1).join('/')}/`;
  return p.endsWith('/') ? p : `${p}/`;
}

function getSessionID() {
  const key = 'passkey_demo_session_id';
  let sid = sessionStorage.getItem(key);
  if (!sid) {
    sid = `${Date.now()}-${Math.random().toString(36).slice(2, 12)}`;
    sessionStorage.setItem(key, sid);
  }
  return sid;
}

async function api(path, method = 'GET', body) {
  const base = getApiBasePath();
  const clean = String(path || '').replace(/^\/+/, '');
  const res = await fetch(`${base}${clean}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Demo-Session': getSessionID() },
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

function b64urlToBuffer(v) {
  const pad = '='.repeat((4 - (v.length % 4)) % 4);
  const b64 = (v + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function bufferToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function normalizeOptions(raw) {
  const options = raw.publicKey ? raw : { publicKey: raw };
  const pk = options.publicKey;
  pk.challenge = b64urlToBuffer(pk.challenge);
  if (typeof pk.user?.id === 'string') pk.user.id = b64urlToBuffer(pk.user.id);
  if (Array.isArray(pk.allowCredentials)) pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64urlToBuffer(c.id) }));
  if (Array.isArray(pk.excludeCredentials)) pk.excludeCredentials = pk.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuffer(c.id) }));
  return options;
}

function credentialToJSON(cred) {
  const response = {};
  for (const k of ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle', 'attestationObject']) {
    if (cred.response && cred.response[k]) response[k] = bufferToB64url(cred.response[k]);
  }
  return { id: cred.id, rawId: bufferToB64url(cred.rawId), type: cred.type, response, clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {} };
}

function App() {
  const [payload, setPayload] = useState('{"to":"0x1234","amount":"1"}');
  const [publicKeyName, setPublicKeyName] = useState('');
  const [requestId, setRequestId] = useState('');
  const [taskId, setTaskId] = useState('');
  const [txId, setTxId] = useState('');
  const [signTxId, setSignTxId] = useState('');
  const [action, setAction] = useState('APPROVE');
  const [userName, setUserName] = useState('Not logged in');
  const [pending, setPending] = useState([]);
  const [pendingAppInstanceId, setPendingAppInstanceId] = useState('');
  const [pendingPublicKeyName, setPendingPublicKeyName] = useState('');
  const [mine, setMine] = useState([]);
  const [result, setResult] = useState('ready');
  const [msg, setMsg] = useState({});

  const setOp = (k, ok, text) => setMsg((m) => ({ ...m, [k]: { ok, text } }));
  const show = (v) => setResult(typeof v === 'string' ? v : JSON.stringify(v, null, 2));

  const onLogin = async () => {
    try {
      const optsRes = await api('/api/login/options');
      if (!optsRes.success) throw new Error(optsRes.error || 'login options failed');
      const sid = Number(optsRes.data.login_session_id);
      const cred = await navigator.credentials.get(normalizeOptions(optsRes.data.options));
      const verifyRes = await api('/api/login/verify', 'POST', { login_session_id: sid, credential: credentialToJSON(cred) });
      show(verifyRes);
      if (!verifyRes.success) throw new Error(verifyRes.error || 'login verify failed');
      setUserName(verifyRes.data?.display_name || 'Logged in');
      setOp('login', true, 'Login success');
    } catch (e) {
      show({ error: String(e) });
      setOp('login', false, `Login failed: ${String(e)}`);
    }
  };

  const onSignInit = async () => {
    try {
      const keyName = String(publicKeyName || '').trim();
      if (!keyName) throw new Error('public_key_name is required');
      const raw = String(payload || '').trim();
      if (!raw) throw new Error('payload is required');
      let body = raw;
      try { body = JSON.parse(raw); } catch (_) {}
      const res = await api('/api/sign', 'POST', { public_key_name: keyName, payload: body });
      show(res);
      if (!res.success) throw new Error(res.error || 'sign failed');
      setRequestId(String(res.data?.request_id || ''));
      setTxId(String(res.data?.tx_id || ''));
      setSignTxId(String(res.data?.tx_id || ''));
      setOp('sign', true, `Sign submitted: ${res.data?.status || '-'}`);
    } catch (e) {
      show({ error: String(e) });
      setOp('sign', false, `Sign failed: ${String(e)}`);
    }
  };

  const onPending = async () => {
    const query = new URLSearchParams();
    if (String(pendingAppInstanceId || '').trim()) {
      query.set('app_instance_id', String(pendingAppInstanceId).trim());
    }
    if (String(pendingPublicKeyName || '').trim()) {
      query.set('public_key_name', String(pendingPublicKeyName).trim());
    }
    const suffix = query.toString() ? `?${query.toString()}` : '';
    const res = await api(`/api/approvals/pending${suffix}`);
    show(res);
    if (res.success) {
      setPending(Array.isArray(res?.data?.approvals) ? res.data.approvals : []);
      setOp('pending', true, 'Fetched pending');
    } else {
      setOp('pending', false, res.error || 'fetch failed');
    }
  };

  const onConfirm = async () => {
    try {
      const rid = Number(requestId);
      const challenge = await api(`/api/approvals/request/${rid}/challenge`);
      if (!challenge.success) throw new Error(challenge.error || 'challenge failed');
      const cred = await navigator.credentials.get(normalizeOptions(challenge.data));
      const res = await api(`/api/approvals/request/${rid}/confirm`, 'POST', { credential: credentialToJSON(cred) });
      show(res);
      if (!res.success) throw new Error(res.error || 'confirm failed');
      setTaskId(String(res.data?.task_id || ''));
      setOp('confirm', true, 'Confirm success');
    } catch (e) {
      show({ error: String(e) });
      setOp('confirm', false, `Confirm failed: ${String(e)}`);
    }
  };

  const onAction = async () => {
    try {
      const tid = Number(taskId);
      const challenge = await api(`/api/approvals/${tid}/challenge`);
      if (!challenge.success) throw new Error(challenge.error || 'challenge failed');
      const cred = await navigator.credentials.get(normalizeOptions(challenge.data.options || challenge.data));
      const res = await api(`/api/approvals/${tid}/action`, 'POST', { action, credential: credentialToJSON(cred) });
      show(res);
      if (!res.success) throw new Error(res.error || 'action failed');
      setOp('action', true, 'Action success');
    } catch (e) {
      show({ error: String(e) });
      setOp('action', false, `Action failed: ${String(e)}`);
    }
  };

  const onMine = async () => {
    const res = await api('/api/requests/mine');
    show(res);
    if (res.success) {
      setMine(Array.isArray(res?.data?.requests) ? res.data.requests : []);
      setOp('mine', true, 'Fetched mine');
    } else {
      setOp('mine', false, res.error || 'fetch failed');
    }
  };

  const onSign = async () => {
    const res = await api(`/api/signature/by-tx/${encodeURIComponent(signTxId)}`);
    show(res);
    setOp('sign', !!res.success, res.success ? 'Query success' : (res.error || 'query failed'));
  };

  const msgNode = (k) => {
    const m = msg[k];
    if (!m) return null;
    return html`<div className=${`msg ${m.ok ? 'ok' : 'err'}`}>${m.text}</div>`;
  };

  const pendingItems = useMemo(() => pending.map((a) => html`
    <div className="item" onClick=${() => { setTaskId(String(a.id || '')); setTxId(String(a.tx_id || '')); setSignTxId(String(a.tx_id || '')); }}>
      <div><b>Task</b> #${a.id} <b>Status</b> ${a.status || '-'}</div>
      <div><b>App</b> ${a.application_name || a.app_name || a.application_id || '-'} <b>Key</b> ${a.public_key_name || a.key_name || a.public_key_id || '-'}</div>
      <div><b>Initiator</b> ${a.requested_by_display_name || a.requested_by_passkey_user_id || '-'}</div>
      <div><b>Tx</b> ${a.tx_id || '-'} <b>Level</b> ${a.current_level || '-'}</div>
    </div>
  `), [pending]);

  const myItems = useMemo(() => mine.map((r) => html`
    <div className="item" onClick=${() => setSignTxId(String(r.tx_id || ''))}>
      <div><b>Tx</b> ${r.tx_id || '-'}</div>
      <div><b>Status</b> ${r.status || '-'} <b>Sign</b> ${r.sign_status || '-'}</div>
      <div><b>Created</b> ${r.created_at || '-'} <b>Updated</b> ${r.updated_at || '-'}</div>
      <div><b>Signature</b> ${r.signature || '-'}</div>
    </div>
  `), [mine]);

  return html`
    <div className="wrap">
      <h1>Passkey Approval React Demo</h1>
      <div className="hint">React UI on top of the same SDK demo API</div>
      <div className="grid">
        <section className="card">
          <h2>1) Passkey Login</h2>
          <button onClick=${onLogin}>Passkey Login</button>
          ${msgNode('login')}
          <label>Current user</label>
          <input value=${userName} readOnly />
        </section>

        <section className="card">
          <h2>2) Initiate By Sign</h2>
          <label>public_key_name</label>
          <input value=${publicKeyName} onInput=${(e) => setPublicKeyName(e.target.value)} placeholder="e.g. my-key" />
          <label>payload (JSON or plain text)</label>
          <textarea value=${payload} onInput=${(e) => setPayload(e.target.value)}></textarea>
          <button onClick=${onSignInit}>Sign (Auto Init Approval)</button>
          ${msgNode('sign')}
          <label>request_id</label>
          <input value=${requestId} onInput=${(e) => setRequestId(e.target.value)} />
          <label>tx_id</label>
          <input value=${txId} readOnly />
        </section>

        <section className="card">
          <h2>3) Pending</h2>
          <label>app_instance_id (optional)</label>
          <input value=${pendingAppInstanceId} onInput=${(e) => setPendingAppInstanceId(e.target.value)} placeholder="e.g. app-demo-001" />
          <label>public_key_name (optional, with app_instance_id)</label>
          <input value=${pendingPublicKeyName} onInput=${(e) => setPendingPublicKeyName(e.target.value)} placeholder="e.g. pk-alpha" />
          <button onClick=${onPending}>Get Pending</button>
          ${msgNode('pending')}
          <div className="list">${pendingItems.length ? pendingItems : html`<div className="hint">No pending approvals</div>`}</div>
        </section>

        <section className="card">
          <h2>4) Confirm</h2>
          <button onClick=${onConfirm}>Challenge + Confirm</button>
          ${msgNode('confirm')}
          <label>task_id</label>
          <input value=${taskId} onInput=${(e) => setTaskId(e.target.value)} />
        </section>

        <section className="card">
          <h2>5) Action</h2>
          <label>action</label>
          <input value=${action} onInput=${(e) => setAction(e.target.value)} />
          <button onClick=${onAction}>Challenge + Action</button>
          ${msgNode('action')}
        </section>

        <section className="card">
          <h2>6) My Requests + Signature</h2>
          <button onClick=${onMine}>Refresh My Requests</button>
          ${msgNode('mine')}
          <div className="list">${myItems.length ? myItems : html`<div className="hint">No requests</div>`}</div>
          <label>tx_id</label>
          <input value=${signTxId} onInput=${(e) => setSignTxId(e.target.value)} />
          <button onClick=${onSign}>Query Signature</button>
          ${msgNode('sign')}
        </section>

        <section className="card">
          <h2>Result</h2>
          <pre>${result}</pre>
        </section>
      </div>
    </div>
  `;
}

createRoot(document.getElementById('app')).render(html`<${App} />`);
