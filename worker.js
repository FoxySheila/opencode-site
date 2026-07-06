// worker.js — Cloudflare Worker: token-gated opencode landing page
// Tokens validated against Workers KV (not single-password).
// Session: stateless HMAC-signed cookie (inspired by sitepass).
// Content: inlined HTML+CSS — no reverse proxy needed.

// ── Embedded site content (dark theme, inline CSS, SVG logo) ──

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenCode — Private Access</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:#0d0d0f;color:#cfcecd;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif}
body{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-container{text-align:center;padding:2rem;max-width:400px;width:100%}
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
    </svg>
  </div>
  <h1>Enter your access token</h1>
  {{ERROR_HTML}}
  <form class="token-form" method="post" action="/login">
    <input type="password" name="token" placeholder="Paste your token" autofocus required spellcheck="false" autocomplete="off">
    <button type="submit">Continue</button>
  </form>
  <div class="footer"><span class="status-dot"></span>OpenCode Private Access</div>
</div>
</body>
</html>`;

const SITE_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenCode — The open source AI coding agent</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:#0d0d0f;color:#cfcecd;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,sans-serif;line-height:1.6;-webkit-font-smoothing:antialiased}
.container{max-width:960px;margin:0 auto;padding:2rem 1.5rem}
/* nav */
nav{display:flex;align-items:center;justify-content:space-between;padding:.75rem 1.5rem;border-bottom:1px solid #1a1a1e}
nav .logo svg{height:24px;width:auto}
nav a{color:#8a8a8a;text-decoration:none;font-size:.875rem;transition:color .2s}
nav a:hover{color:#e4e4e7}
nav .links{display:flex;gap:1.5rem;align-items:center}
/* hero */
.hero{text-align:center;padding:5rem 0 3rem}
.hero h1{font-size:clamp(2rem,5vw,3.25rem);font-weight:700;letter-spacing:-.03em;color:#f1ecec;margin-bottom:1rem;line-height:1.15}
.hero p{font-size:1.15rem;color:#8a8a8a;max-width:600px;margin:0 auto 2rem}
.install-block{display:flex;flex-wrap:wrap;gap:.5rem;justify-content:center;margin-bottom:1rem}
.install-block code{background:#1a1a1e;border:1px solid #2a2a2e;border-radius:8px;padding:.625rem 1rem;font-family:'SF Mono','Cascadia Code','Fira Code',monospace;font-size:.85rem;color:#e4e4e7}
.install-tabs{display:flex;gap:.25rem;justify-content:center;margin-bottom:1.5rem;flex-wrap:wrap}
.install-tabs a{color:#636363;text-decoration:none;font-size:.8rem;padding:.25rem .75rem;border-radius:4px;transition:all .2s}
.install-tabs a:hover,.install-tabs a.active{color:#e4e4e7;background:#1a1a1e}
/* features */
.features{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;padding:3rem 0}
.feature-card{background:#121215;border:1px solid #1a1a1e;border-radius:12px;padding:1.5rem;transition:border-color .3s}
.feature-card:hover{border-color:#2a2a2e}
.feature-card h3{font-size:.95rem;font-weight:600;color:#e4e4e7;margin-bottom:.5rem}
.feature-card p{font-size:.85rem;color:#8a8a8a;line-height:1.5}
/* stats */
.stats{display:flex;justify-content:center;gap:3rem;padding:2.5rem 0;flex-wrap:wrap}
.stat{text-align:center}
.stat-num{font-size:1.75rem;font-weight:700;color:#f1ecec}
.stat-label{font-size:.8rem;color:#636363;margin-top:.15rem}
/* sections */
.section{padding:2.5rem 0}
.section h2{font-size:1.5rem;font-weight:600;color:#f1ecec;margin-bottom:1.25rem;text-align:center}
.section p{color:#8a8a8a;max-width:680px;margin:0 auto 1rem;text-align:center}
.links{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;padding:1rem 0}
.links a{display:inline-flex;align-items:center;gap:.5rem;background:#1a1a1e;border:1px solid #2a2a2e;border-radius:8px;padding:.625rem 1.25rem;color:#e4e4e7;text-decoration:none;font-size:.875rem;transition:all .2s}
.links a:hover{background:#2a2a2e;border-color:#636363}
.logout{text-align:center;padding:2rem 0}
.logout a{color:#636363;font-size:.8rem;text-decoration:none}
.logout a:hover{color:#f87171}
/* faq */
.faq-item{margin-bottom:1rem;background:#121215;border:1px solid #1a1a1e;border-radius:8px;padding:1rem 1.25rem}
.faq-item h4{font-size:.9rem;font-weight:600;color:#e4e4e7;margin-bottom:.35rem}
.faq-item p{font-size:.85rem;color:#8a8a8a;margin:0;text-align:left}
footer{text-align:center;padding:2rem 0;border-top:1px solid #1a1a1e;font-size:.8rem;color:#52525b}
</style>
</head>
<body>
<nav>
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
    </svg>
  </div>
  <div class="links">
    <a href="https://opencode.ai">opencode.ai</a>
    <a href="https://github.com/anomalyco/opencode">GitHub</a>
    <a href="/logout">Logout</a>
  </div>
</nav>
<div class="container">
  <div class="hero">
    <h1>The open source AI coding agent</h1>
    <p>Free models included or connect any model from any provider, including Claude, GPT, Gemini and more.</p>
    <div class="install-tabs">
      <a class="active" href="#" onclick="return false">curl</a>
      <a href="#" onclick="return false">npm</a>
      <a href="#" onclick="return false">brew</a>
    </div>
    <div class="install-block">
      <code>curl -fsSL https://opencode.ai/install | bash</code>
    </div>
  </div>
  <div class="stats">
    <div class="stat"><div class="stat-num">160K</div><div class="stat-label">GitHub Stars</div></div>
    <div class="stat"><div class="stat-num">900</div><div class="stat-label">Contributors</div></div>
    <div class="stat"><div class="stat-num">7.5M</div><div class="stat-label">Monthly Devs</div></div>
  </div>
  <div class="features">
    <div class="feature-card"><h3>LSP Enabled</h3><p>Automatically loads the right language servers for the LLM — context-aware completions.</p></div>
    <div class="feature-card"><h3>Multi-Session</h3><p>Start multiple agents in parallel on the same project. Work on several tasks at once.</p></div>
    <div class="feature-card"><h3>Any Model</h3><p>75+ LLM providers through Models.dev. Use Claude, GPT, Gemini, local models, or your own.</p></div>
    <div class="feature-card"><h3>Privacy First</h3><p>OpenCode does not store any of your code or context data. Operates in sensitive environments.</p></div>
    <div class="feature-card"><h3>Any Editor</h3><p>Available as a terminal interface, desktop app (macOS, Windows, Linux), and IDE extension.</p></div>
    <div class="feature-card"><h3>Share Links</h3><p>Share a link to any session for reference or debugging with your team.</p></div>
  </div>
  <div class="section">
    <h2>About OpenCode</h2>
    <p>OpenCode is an open source AI coding agent that helps you write code in your terminal, IDE, or desktop. With over 160,000 GitHub stars and 900 contributors, it's trusted by millions of developers every month.</p>
    <div class="links">
      <a href="https://opencode.ai">Visit opencode.ai →</a>
      <a href="https://github.com/anomalyco/opencode">GitHub Repository →</a>
      <a href="https://opencode.ai/docs">Documentation →</a>
    </div>
  </div>
  <div class="section">
    <h2>FAQ</h2>
    <div class="faq-item">
      <h4>What is OpenCode?</h4>
      <p>An open source AI coding agent that works in your terminal. Free models included, or bring your own from any provider.</p>
    </div>
    <div class="faq-item">
      <h4>How much does it cost?</h4>
      <p>OpenCode is free and open source. You can use included free models or connect your own API keys for premium models.</p>
    </div>
    <div class="faq-item">
      <h4>What about privacy?</h4>
      <p>OpenCode does not store your code or context data. It's designed for privacy-sensitive environments.</p>
    </div>
  </div>
</div>
<footer>
  OpenCode — <a href="https://github.com/anomalyco/opencode" style="color:#636363;text-decoration:none">GitHub</a> · <a href="https://opencode.ai/docs" style="color:#636363;text-decoration:none">Docs</a> · <a href="https://opencode.ai" style="color:#636363;text-decoration:none">opencode.ai</a>
</footer>
</body>
</html>`;

// ── Crypto helpers (use Web Crypto API available in Workers) ──

async function hmacSha256(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=+$/, '');
}

function base64UrlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// ── Token hashing ──

async function sha256Hex(input) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Session cookie management (stateless HMAC) ──

async function createSessionCookie(secret) {
  const expires = Math.floor(Date.now() / 1000) + 30 * 86400; // 30 days
  const payload = `${expires}`;
  const sig = await hmacSha256(secret, payload + ':opencode');
  const cookie = btoa(payload).replace(/=+$/, '') + '.' + sig;
  return { cookie, expires };
}

async function validateSession(cookie, secret) {
  if (!cookie || !cookie.includes('.')) return false;
  const [encodedExpiry, sig] = cookie.split('.');
  let expiry;
  try {
    expiry = parseInt(atob(encodedExpiry), 10);
  } catch { return false; }
  if (Date.now() / 1000 > expiry) return false;
  const expectedSig = await hmacSha256(secret, `${expiry}:opencode`);
  if (sig !== expectedSig) return false;
  return true;
}

// ── Rate limiting (KV-backed) ──

async function checkRateLimit(env, ip) {
  if (!env.TOKENS) return true;
  const key = `ratelimit:${ip}`;
  const val = await env.TOKENS.get(key);
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
    until = count >= 5 ? now + 900 : now + 60; // 15 min ban after 5 fails
  }
  await env.TOKENS.put(key, JSON.stringify({ count, until }), { expirationTtl: count >= 5 ? 900 : 60 });
}

// ── Route handlers ──

function renderLogin(error) {
  const errorHtml = error
    ? `<div class="error">${error}</div>`
    : '';
  return new Response(LOGIN_PAGE.replace('{{ERROR_HTML}}', errorHtml), {
    headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

function renderSite() {
  return new Response(SITE_PAGE, {
    headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

async function handleLogin(request, env) {
  // Rate limit
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, ip))) {
    return renderLogin('Too many attempts. Try again in 15 minutes.');
  }
  // Parse form body
  let token;
  const ct = request.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) {
    try { const j = await request.json(); token = j.token; } catch { token = null; }
  } else {
    try {
      const form = await request.formData();
      token = form.get('token');
    } catch { token = null; }
  }
  if (!token || typeof token !== 'string' || token.length < 8) {
    return renderLogin('Invalid token format.');
  }
  // Hash token and look up in KV (value is age-encrypted blob, not parsed)
  const hash = await sha256Hex(token);
  let entry;
  try { entry = await env.TOKENS.get(`tok_${hash}`); } catch { entry = null; }
  if (!entry) {
    await recordAttempt(env, ip);
    return renderLogin('Invalid token.');
  }
  // KV TTL handles expiry automatically — if the key exists, it's valid
  // Create session
  const { cookie, expires } = await createSessionCookie(env.SESSION_SECRET);
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

// ── Main entry ──

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST', 'Access-Control-Allow-Headers': '*' } });
    }
    const url = new URL(request.url);
    const path = url.pathname;
    // POST /login
    if (path === '/login' && request.method === 'POST') {
      return handleLogin(request, env);
    }
    // GET /logout
    if (path === '/logout') {
      return handleLogout();
    }
    // Everything else: check session
    if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 16) {
      return new Response('Server misconfigured: SESSION_SECRET not set', { status: 503 });
    }
    const cookieHeader = request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/(?:^|;\s*)opencode_session=([^;]+)/);
    const sessionCookie = match ? match[1] : null;
    if (sessionCookie && await validateSession(sessionCookie, env.SESSION_SECRET)) {
      return renderSite();
    }
    // Redirect to clean login URL
    if (path === '/') {
      return renderLogin(null);
    }
    return renderLogin(null);
  }
};
