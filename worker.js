// worker.js — Cloudflare Worker: token-gated opencode.ai proxy
// Authenticates via Sigil token, proxies all requests to opencode.ai
// with the admin's OPENCODE_AUTH cookie injected.
// Per-token session isolation via KV tracking.

const OPENCODE_BASE = 'https://opencode.ai';

// ── Embedded login page ──

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sigil — Private Access</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:#0d0d0f;color:#cfcecd;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif}
body{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-container{text-align:center;padding:2rem;max-width:420px;width:100%}
.logo{margin-bottom:1.5rem}
.logo svg{width:180px;height:auto}
h1{font-size:1.25rem;font-weight:500;color:#8a8a8a;margin-bottom:2rem;letter-spacing:.02em}
.token-form{display:flex;flex-direction:column;gap:.75rem}
.token-form input[type=text],.token-form input[type=password]{background:#1a1a1e;border:1px solid #2a2a2e;border-radius:8px;padding:.875rem 1rem;color:#e4e4e7;font-size:1rem;outline:none;transition:border-color .2s}
.token-form input[type=text]:focus,.token-form input[type=password]:focus{border-color:#636363}
.token-form button{background:#e4e4e7;color:#0d0d0f;border:none;border-radius:8px;padding:.875rem;font-size:.95rem;font-weight:600;cursor:pointer;transition:opacity .2s;margin-top:.25rem}
.token-form button:hover{opacity:.85}
.error{background:#2d1517;border:1px solid #5c2024;color:#f87171;border-radius:8px;padding:.75rem 1rem;font-size:.875rem;margin-bottom:1rem}
.footer{margin-top:2rem;font-size:.75rem;color:#52525b}
.status-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:#22c55e;margin-right:4px;vertical-align:middle}
.or-divider{display:flex;align-items:center;gap:.75rem;margin:.75rem 0;color:#52525b;font-size:.8rem}
.or-divider::before,.or-divider::after{content:"";flex:1;height:1px;background:#1a1a1e}
.stego-upload{position:relative}
.stego-upload input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}
.stego-upload label{display:block;background:#1a1a1e;border:1px dashed #2a2a2e;border-radius:8px;padding:.75rem;font-size:.85rem;color:#636363;transition:all .2s;cursor:pointer}
.stego-upload label:hover,.stego-upload label.dragover{border-color:#636363;color:#8a8a8a}
.stego-upload label.done{border-color:#22c55e;color:#22c55e}
#stego-status{font-size:.75rem;color:#636363;margin-top:-.25rem;min-height:1.2em}
</style>
</head>
<body>
<div class="login-container">
  <div class="logo">
    <svg viewBox="0 0 234 42" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M18 30H6V18H18V30Z" fill="#CFCECD"/>
      <path d="M18 12H6V30H18V12ZM24 36H0V6H24V36Z" fill="#636363"/>
      <path d="M48 30H36V18H48V30Z" fill="#CFCECD"/>
      <path d="M36 30H48V12H36V30ZM54 36H36V42H30V6H54V36Z" fill="#636363"/>
      <path d="M84 24V30H66V24H84Z" fill="#CFCECD"/>
      <path d="M84 24H66V30H84V36H60V6H84V24ZM66 18H78V12H66V18Z" fill="#636363"/>
      <path d="M108 36H96V18H108V36Z" fill="#CFCECD"/>
      <path d="M108 12H96V36H90V6H108V12ZM114 36H108V12H114V36Z" fill="#636363"/>
      <path d="M144 30H126V18H144V30Z" fill="#CFCECD"/>
      <path d="M144 12H126V30H144V36H120V6H144V12Z" fill="#211E1E"/>
      <path d="M168 30H156V18H168V30Z" fill="#CFCECD"/>
      <path d="M168 12H156V30H168V12ZM174 36H150V6H174V36Z" fill="#211E1E"/>
      <path d="M198 30H186V18H198V30Z" fill="#CFCECD"/>
      <path d="M198 12H186V30H198V12ZM204 36H180V6H198V0H204V36Z" fill="#211E1E"/>
      <path d="M234 24V30H216V24H234Z" fill="#CFCECD"/>
      <path d="M234 24H216V30H234V36H210V6H234V24ZM216 18H228V12H216V18Z" fill="#211E1E"/>
    </svg>
  </div>
  <h1>Enter your access token</h1>
  {{ERROR_HTML}}
  <form class="token-form" method="post" action="/login">
    <input type="password" name="token" id="token-input" placeholder="Paste your token" autofocus required spellcheck="false" autocomplete="off">
    <button type="submit">Continue</button>
  </form>
  <div class="or-divider">or</div>
  <div class="stego-upload">
    <input type="file" id="stego-file" accept="image/png,image/jpeg,image/webp">
    <label for="stego-file" id="stego-label">Insert token image</label>
  </div>
  <div id="stego-status"></div>
  <div class="footer"><span class="status-dot"></span>Sigil Private Access</div>
</div>
<script>
const CRUN_MAGIC = new Uint8Array([0x43,0x52,0x55,0x4E]);
function readU16LE(buf, off) { return buf[off] | (buf[off+1] << 8); }
function readU32LE(buf, off) { return buf[off] | (buf[off+1]<<8) | (buf[off+2]<<16) | (buf[off+3]<<24); }
async function lsbExtractToken(pixels, w, h) {
  const bits = [];
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 4;
      bits.push(pixels[i] & 1);
      bits.push(pixels[i+1] & 1);
      bits.push(pixels[i+2] & 1);
    }
  }
  if (bits.length < 32) return null;
  const toBytes = (start, count) => {
    const b = new Uint8Array(count);
    for (let i = 0; i < count; i++) {
      let byte = 0;
      for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[start + i*8 + j];
      b[i] = byte;
    }
    return b;
  };
  const metaLen = readU32LE(toBytes(0, 4), 0);
  const totalBits = 32 + (metaLen + 4) * 8;
  if (bits.length < totalBits) return null;
  const raw = toBytes(32, metaLen + 4);
  const payload = new Uint8Array(raw.slice(0, metaLen));
  const checksum = raw.slice(metaLen, metaLen + 4);
  const hash = await crypto.subtle.digest('SHA-256', payload);
  const h = new Uint8Array(hash);
  if (h[0] !== checksum[0] || h[1] !== checksum[1] || h[2] !== checksum[2] || h[3] !== checksum[3]) return null;
  if (payload[0] !== CRUN_MAGIC[0] || payload[1] !== CRUN_MAGIC[1] || payload[2] !== CRUN_MAGIC[2] || payload[3] !== CRUN_MAGIC[3]) return null;
  let off = 4;
  const count = readU32LE(payload, off); off += 4;
  for (let i = 0; i < count; i++) {
    if (off + 2 > payload.length) break;
    const nameLen = readU16LE(payload, off); off += 2;
    if (off + nameLen + 4 > payload.length) break;
    const name = new TextDecoder().decode(payload.slice(off, off + nameLen));
    off += nameLen;
    const dataLen = readU32LE(payload, off); off += 4;
    if (off + dataLen > payload.length) break;
    if (name === '.token') {
      return new TextDecoder().decode(payload.slice(off, off + dataLen));
    }
    off += dataLen;
  }
  return null;
}
document.getElementById('stego-file').addEventListener('change', async function(e) {
  const file = e.target.files[0];
  if (!file) return;
  const status = document.getElementById('stego-status');
  const label = document.getElementById('stego-label');
  status.textContent = 'Reading image...';
  label.textContent = file.name;
  label.className = '';
  try {
    const bitmap = await createImageBitmap(file);
    const canvas = document.createElement('canvas');
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(bitmap, 0, 0);
    bitmap.close();
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const token = await lsbExtractToken(imgData.data, canvas.width, canvas.height);
    if (token && token.startsWith('opc_')) {
      document.getElementById('token-input').value = token;
      label.className = 'done';
      label.textContent = '\u2713 ' + file.name;
      status.textContent = 'Token extracted \u2713 \u2014 click Continue';
      setTimeout(() => document.querySelector('.token-form button').click(), 600);
    } else {
      label.className = '';
      label.textContent = '\u2717 No token found in image';
      status.textContent = 'Not a valid stego image, or token format unrecognized.';
    }
  } catch(err) {
    label.className = '';
    label.textContent = '\u2717 Error reading image';
    status.textContent = err.message;
  }
});
</script>
</body>
</html>`;

// ── Crypto helpers ──

async function hmacSha256(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=+$/, '');
}

async function sha256Hex(input) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Session cookie ──

async function createSessionCookie(secret, tokenHash) {
  const expires = Math.floor(Date.now() / 1000) + 30 * 86400;
  const payload = `${expires}:${tokenHash}`;
  const sig = await hmacSha256(secret, payload);
  const cookie = btoa(payload).replace(/=+$/, '') + '.' + sig;
  return { cookie, expires, tokenHash };
}

async function validateSession(cookie, secret) {
  if (!cookie || !cookie.includes('.')) return { valid: false };
  const [encodedPayload, sig] = cookie.split('.');
  let payload;
  try { payload = atob(encodedPayload); } catch { return { valid: false }; }
  const colon = payload.lastIndexOf(':');
  if (colon < 0) return { valid: false };
  const expiry = parseInt(payload.substring(0, colon), 10);
  const tokenHash = payload.substring(colon + 1);
  if (isNaN(expiry) || Date.now() / 1000 > expiry) return { valid: false };
  const expectedSig = await hmacSha256(secret, payload);
  if (sig !== expectedSig) return { valid: false };
  return { valid: true, tokenHash };
}

// ── Token auth (cookie for web, Bearer header for CLI) ──

async function authTokenHash(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    if (token && token.startsWith('opc_')) {
      const hash = await sha256Hex(token);
      const entry = await env.TOKENS.get(`tok_${hash}`);
      if (entry) return hash;
    }
    return null;
  }
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/(?:^|;\s*)opencode_session=([^;]+)/);
  const sessionCookie = match ? match[1] : null;
  if (sessionCookie) {
    const session = await validateSession(sessionCookie, env.SESSION_SECRET);
    if (session.valid) return session.tokenHash;
  }
  return null;
}

// ── Rate limiting ──

async function checkRateLimit(env, ip) {
  if (!env.TOKENS) return true;
  const val = await env.TOKENS.get(`ratelimit:${ip}`);
  if (!val) return true;
  const { count, until } = JSON.parse(val);
  if (Date.now() / 1000 < until) return false;
  return true;
}

async function recordAttempt(env, ip) {
  if (!env.TOKENS) return;
  const key = `ratelimit:${ip}`;
  const val = await env.TOKENS.get(key);
  const now = Math.floor(Date.now() / 1000);
  let count = 1, until = now + 60;
  if (val) {
    const prev = JSON.parse(val);
    count = prev.count + 1;
    until = count >= 5 ? now + 900 : now + 60;
  }
  await env.TOKENS.put(key, JSON.stringify({ count, until }), { expirationTtl: count >= 5 ? 900 : 60 });
}

// ── Session ownership helpers ──

async function getTokenSessions(env, tokenHash) {
  try {
    const raw = await env.TOKENS.get(`tok_${tokenHash}:sessions`);
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

async function ownsSession(env, tokenHash, sessionId) {
  const sessions = await getTokenSessions(env, tokenHash);
  return sessions.includes(sessionId);
}

async function addSession(env, tokenHash, sessionId) {
  const sessions = await getTokenSessions(env, tokenHash);
  if (!sessions.includes(sessionId)) {
    sessions.push(sessionId);
    await env.TOKENS.put(`tok_${tokenHash}:sessions`, JSON.stringify(sessions));
  }
}

async function removeSession(env, tokenHash, sessionId) {
  const sessions = await getTokenSessions(env, tokenHash);
  const idx = sessions.indexOf(sessionId);
  if (idx >= 0) {
    sessions.splice(idx, 1);
    await env.TOKENS.put(`tok_${tokenHash}:sessions`, JSON.stringify(sessions));
  }
}

// ── Token validation ──

async function validateToken(token, env, ip) {
  if (!token || typeof token !== 'string' || token.length < 8) return null;
  const hash = await sha256Hex(token);
  const tokKey = `tok_${hash}`;
  let entry;
  try { entry = await env.TOKENS.get(tokKey); } catch { entry = null; }
  if (!entry) {
    if (ip) await recordAttempt(env, ip);
    return null;
  }
  const usesKey = `${tokKey}:u`;
  let usesEntry;
  try { usesEntry = await env.TOKENS.get(usesKey); } catch { usesEntry = null; }
  if (usesEntry) {
    try {
      const uses = JSON.parse(usesEntry);
      if (uses.m > 0 && uses.n >= uses.m) {
        if (ip) await recordAttempt(env, ip);
        return null;
      }
      uses.n = (uses.n || 0) + 1;
      await env.TOKENS.put(usesKey, JSON.stringify(uses));
    } catch {}
  }
  return hash;
}

// ── Login/logout handlers ──

function renderLogin(error) {
  const errorHtml = error ? `<div class="error">${error}</div>` : '';
  return new Response(LOGIN_PAGE.replace('{{ERROR_HTML}}', errorHtml), {
    headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

async function handleLogin(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, ip))) {
    return renderLogin('Too many attempts. Try again in 15 minutes.');
  }
  let token;
  const ct = request.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) {
    try { const j = await request.json(); token = j.token; } catch { token = null; }
  } else {
    try { const form = await request.formData(); token = form.get('token'); } catch { token = null; }
  }
  const hash = await validateToken(token, env, ip);
  if (!hash) return renderLogin('Invalid token.');
  const { cookie } = await createSessionCookie(env.SESSION_SECRET, hash);
  const url = new URL(request.url);
  const next = url.searchParams.get('next') || '/';
  return new Response(null, {
    status: 302,
    headers: {
      'Location': next,
      'Set-Cookie': `opencode_session=${cookie}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${30 * 86400}`,
    }
  });
}

function handleLogout() {
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/',
      'Set-Cookie': 'opencode_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0',
    }
  });
}

// ── Proxy to opencode.ai ──

function cloneHeaders(headers) {
  const h = new Headers();
  for (const [k, v] of headers) h.set(k, v);
  return h;
}

async function proxyToOpencode(request, env, tokenHash) {
  const url = new URL(request.url);
  const targetPath = url.pathname + url.search;
  const targetUrl = OPENCODE_BASE + targetPath;

  // Build proxied headers
  const headers = cloneHeaders(request.headers);
  headers.delete('Host');
  headers.delete('Cookie');
  headers.delete('Cf-*');
  headers.delete('CF-*');
  headers.delete('X-Forwarded-*');
  headers.delete('X-Real-IP');
  headers.delete('Cf-Ray');
  headers.delete('Cf-Connecting-Ip');
  headers.delete('Cf-Visitor');
  headers.delete('Cf-Cache-Status');
  headers.delete('Cf-Worker');
  headers.delete('Cf-Request-Id');
  headers.set('Cookie', `auth=${env.OPENCODE_AUTH}`);

  // Forward body for non-GET/HEAD
  const body = ['GET', 'HEAD'].includes(request.method) ? null : request.body;

  const proxyResp = await fetch(targetUrl, {
    method: request.method,
    headers,
    body,
    redirect: 'manual',
  });

  // ── Handle redirects (rewrite Location to proxy domain) ──
  if (proxyResp.status >= 300 && proxyResp.status < 400) {
    const location = proxyResp.headers.get('Location');
    if (location) {
      const respHeaders = new Headers();
      respHeaders.set('Location', location.replace(OPENCODE_BASE, ''));
      respHeaders.set('Access-Control-Allow-Origin', '*');
      return new Response(null, { status: proxyResp.status, headers: respHeaders });
    }
  }

  // ── Session-aware response handling ──

  // GET /session — list sessions, filter by token ownership
  if (request.method === 'GET' && url.pathname === '/session') {
    return filterSessionList(proxyResp, env, tokenHash);
  }

  // POST /session — create session, track it
  if (request.method === 'POST' && url.pathname === '/session') {
    return trackCreatedSession(proxyResp, env, tokenHash);
  }

  // /session/:id/* — verify ownership (only if ID looks like a real session ID)
  const sessionMatch = url.pathname.match(/^\/session\/([a-f0-9\-]+)(\/|$)/);
  if (sessionMatch) {
    const sessionId = decodeURIComponent(sessionMatch[1]);
    if (sessionId.length >= 6 && !(await ownsSession(env, tokenHash, sessionId))) {
      return new Response('Forbidden: session does not belong to this token', { status: 403 });
    }
    // DELETE /session/:id — remove from tracking
    if (request.method === 'DELETE' && proxyResp.status < 400) {
      await removeSession(env, tokenHash, sessionId);
      return proxyResp;
    }
    // POST /session/:id/fork — track the new forked session
    if (request.method === 'POST' && url.pathname.endsWith('/fork')) {
      return trackCreatedSession(proxyResp, env, tokenHash);
    }
  }

  // ── Build response ──

  const respHeaders = new Headers();
  const safeHeaders = ['content-type', 'content-length', 'cache-control', 'etag', 'last-modified', 'vary', 'accept-ranges', 'content-range', 'content-encoding', 'transfer-encoding', 'x-request-id'];
  for (const [k, v] of proxyResp.headers) {
    const lk = k.toLowerCase();
    if (safeHeaders.includes(lk)) {
      respHeaders.set(k, v);
    }
  }

  // Strip Set-Cookie from upstream (we manage our own auth)
  respHeaders.set('Access-Control-Allow-Origin', '*');
  respHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  respHeaders.set('Access-Control-Allow-Headers', '*');
  respHeaders.set('Access-Control-Expose-Headers', '*');

  // For HTML pages, inject Sigil toolbar
  const ct = proxyResp.headers.get('Content-Type') || '';
  if (ct.includes('text/html')) {
    const bodyText = await proxyResp.text();
    const toolbar = `<div id="sigil-toolbar" style="all:revert;display:flex;align-items:center;justify-content:space-between;padding:6px 16px;background:#0d0d0f;border-bottom:1px solid #2a2a2e;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;color:#8a8a8a">
  <span><span style="color:#22c55e">\u25CF</span> Sigil <span style="color:#52525b;font-size:11px">${tokenHash.substring(0, 8)}</span></span>
  <a href="/logout" style="color:#636363;text-decoration:none;font-size:12px">Logout \u2192</a>
</div>`;
    const modified = bodyText.replace(/<body[^>]*>/, match => match + toolbar);
    return new Response(modified, {
      status: proxyResp.status,
      headers: respHeaders,
    });
  }

  // Pass through body for non-HTML responses
  return new Response(proxyResp.body, {
    status: proxyResp.status,
    headers: respHeaders,
  });
}

async function filterSessionList(proxyResp, env, tokenHash) {
  const tokenSessions = await getTokenSessions(env, tokenHash);
  const body = await proxyResp.json();
  let filtered;
  if (Array.isArray(body)) {
    filtered = body.filter(s => tokenSessions.includes(s.id));
  } else if (body && typeof body === 'object') {
    filtered = {};
    for (const [k, v] of Object.entries(body)) {
      if (tokenSessions.includes(v.id || k)) {
        filtered[k] = v;
      }
    }
  } else {
    filtered = body;
  }
  return new Response(JSON.stringify(filtered), {
    status: proxyResp.status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

async function trackCreatedSession(proxyResp, env, tokenHash) {
  // Clone the response so we can read the body
  const body = await proxyResp.text();
  let sessionId = null;
  try {
    const data = JSON.parse(body);
    sessionId = data.id || data._id || null;
  } catch {}
  if (sessionId) {
    await addSession(env, tokenHash, sessionId);
  }
  return new Response(body, {
    status: proxyResp.status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

// ── Main entry ──

export default {
  async fetch(request, env) {
    // Validate required secrets
    if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 16) {
      return new Response('Server misconfigured: SESSION_SECRET not set', { status: 503 });
    }
    if (!env.OPENCODE_AUTH) {
      return new Response('Server misconfigured: OPENCODE_AUTH not set', { status: 503 });
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // POST /login — validate token, set session cookie
    if (path === '/login' && request.method === 'POST') {
      return handleLogin(request, env);
    }

    // GET /logout — clear session
    if (path === '/logout') {
      return handleLogout();
    }

    // Auth check: try cookie (web) or Bearer header (CLI)
    const tokenHash = await authTokenHash(request, env);

    if (!tokenHash) {
      // Not authenticated — serve login page for GET /, reject everything else
      if (path === '/' && request.method === 'GET') {
        return renderLogin(null);
      }
      if (path === '/login') {
        return renderLogin(null);
      }
      // API calls without auth get 401
      return new Response('Authentication required. Present token via cookie (web) or Authorization: Bearer <token> (CLI).', { status: 401 });
    }

    // Authenticated — proxy everything to opencode.ai
    return proxyToOpencode(request, env, tokenHash);
  }
};
